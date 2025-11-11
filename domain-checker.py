#!/usr/bin/env python3
"""
MCP Server for checking domain name availability using FastMCP 2.0
Optimized for high-scale operations (up to 500k domains)
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional
from functools import lru_cache
import whois
import dns.resolver
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("domain-checker")

# Configuration for large-scale operations
MAX_CONCURRENT_TASKS = 200  # Limit concurrent DNS/WHOIS operations
MAX_CONCURRENT_WHOIS = 5     # Much stricter limit for WHOIS to avoid bans
WHOIS_RATE_LIMIT = 0.5       # Minimum seconds between WHOIS requests
BATCH_SIZE = 1000            # Process domains in batches for memory efficiency
DNS_CACHE_SIZE = 10000       # Cache DNS results
THREAD_POOL_SIZE = 100       # Custom thread pool size
MAX_RETRIES = 3              # Retry failed operations
RETRY_DELAY = 1.0            # Initial retry delay in seconds

# Create the FastMCP server
mcp = FastMCP(
    name="Domain Checker",
    instructions="When you are asked about domain availability or to check if a domain is available for registration, call the appropriate function."
)

class RateLimiter:
    """Token bucket rate limiter for WHOIS requests"""

    def __init__(self, rate: float):
        self.rate = rate
        self.last_request = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self):
        """Wait until rate limit allows next request"""
        async with self.lock:
            now = time.time()
            time_since_last = now - self.last_request
            if time_since_last < self.rate:
                await asyncio.sleep(self.rate - time_since_last)
            self.last_request = time.time()


class DomainChecker:
    """Domain availability checker optimized for large-scale operations"""

    def __init__(self):
        # Create custom thread pool for blocking I/O
        self.thread_pool = ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE)

        # Semaphores for concurrency control
        self.dns_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
        self.whois_semaphore = asyncio.Semaphore(MAX_CONCURRENT_WHOIS)

        # Rate limiter for WHOIS requests
        self.whois_rate_limiter = RateLimiter(WHOIS_RATE_LIMIT)

        # Statistics tracking
        self.stats = {
            "total_checked": 0,
            "available": 0,
            "unavailable": 0,
            "errors": 0
        }

    def _create_dns_resolver(self) -> dns.resolver.Resolver:
        """Create a new DNS resolver instance (thread-safe)"""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        return resolver
    
    async def check_domain_availability(
        self,
        domain: str,
        skip_whois: bool = False
    ) -> Dict[str, Any]:
        """Check if a domain is available using multiple methods with retry logic"""
        results = {
            "domain": domain,
            "available": None,
            "whois_available": None,
            "dns_resolvable": None,
            "error": None,
            "details": {}
        }

        try:
            # DNS check (fast, required)
            dns_result = await self._check_dns_resolution_with_retry(domain)
            results["dns_resolvable"] = dns_result["resolvable"]
            results["details"]["dns"] = dns_result

            # WHOIS check (slow, optional for large batches)
            if not skip_whois:
                whois_result = await self._check_whois_with_retry(domain)
                results["whois_available"] = whois_result["available"]
                results["details"]["whois"] = whois_result

                # Determine overall availability
                if results["whois_available"] is True and results["dns_resolvable"] is False:
                    results["available"] = True
                elif results["whois_available"] is False:
                    results["available"] = False
                else:
                    results["available"] = None
            else:
                # DNS-only mode: if doesn't resolve, likely available
                if results["dns_resolvable"] is False:
                    results["available"] = True
                elif results["dns_resolvable"] is True:
                    results["available"] = False
                else:
                    results["available"] = None

            # Update stats
            self.stats["total_checked"] += 1
            if results["available"] is True:
                self.stats["available"] += 1
            elif results["available"] is False:
                self.stats["unavailable"] += 1

        except Exception as e:
            results["error"] = str(e)
            self.stats["errors"] += 1
            logger.error(f"Error checking domain {domain}: {e}")

        return results
    
    async def _check_whois_with_retry(self, domain: str) -> Dict[str, Any]:
        """Check WHOIS with rate limiting, semaphore, and retry logic"""
        async with self.whois_semaphore:
            await self.whois_rate_limiter.acquire()

            for attempt in range(MAX_RETRIES):
                try:
                    return await self._check_whois(domain)
                except Exception as e:
                    if attempt < MAX_RETRIES - 1:
                        delay = RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                        logger.warning(
                            f"WHOIS lookup failed for {domain} (attempt {attempt + 1}/{MAX_RETRIES}), "
                            f"retrying in {delay}s: {e}"
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(f"WHOIS lookup failed for {domain} after {MAX_RETRIES} attempts: {e}")
                        return {"available": None, "reason": f"WHOIS lookup failed after retries: {str(e)}"}

    async def _check_whois(self, domain: str) -> Dict[str, Any]:
        """Check domain availability using WHOIS"""
        try:
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(self.thread_pool, whois.whois, domain)

            if whois_data is None:
                return {"available": True, "reason": "No WHOIS data found"}

            if hasattr(whois_data, 'status') and whois_data.status:
                return {
                    "available": False,
                    "reason": "Domain has active status",
                    "status": whois_data.status,
                    "registrar": getattr(whois_data, 'registrar', None),
                    "creation_date": str(getattr(whois_data, 'creation_date', None))
                }

            if hasattr(whois_data, 'registrar') and whois_data.registrar:
                return {
                    "available": False,
                    "reason": "Domain has registrar",
                    "registrar": whois_data.registrar
                }

            return {
                "available": None,
                "reason": "WHOIS data exists but unclear status",
                "raw_data": str(whois_data)[:500]
            }

        except whois.parser.PywhoisError as e:
            return {"available": True, "reason": f"WHOIS parser error: {str(e)}"}
        except Exception as e:
            raise  # Let retry logic handle it
    
    async def _check_dns_resolution_with_retry(self, domain: str) -> Dict[str, Any]:
        """Check DNS with semaphore and retry logic"""
        async with self.dns_semaphore:
            for attempt in range(MAX_RETRIES):
                try:
                    return await self._check_dns_resolution(domain)
                except Exception as e:
                    if attempt < MAX_RETRIES - 1:
                        delay = RETRY_DELAY * (2 ** attempt)
                        logger.debug(
                            f"DNS lookup failed for {domain} (attempt {attempt + 1}/{MAX_RETRIES}), "
                            f"retrying in {delay}s: {e}"
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(f"DNS lookup failed for {domain} after {MAX_RETRIES} attempts: {e}")
                        return {"resolvable": None, "reason": f"DNS lookup failed after retries: {str(e)}"}

    @lru_cache(maxsize=DNS_CACHE_SIZE)
    def _resolve_dns_cached(self, domain: str) -> Optional[List[str]]:
        """Cached DNS resolution (thread-safe, separate resolver per call)"""
        resolver = self._create_dns_resolver()
        try:
            answers = resolver.resolve(domain, 'A')
            return [str(answer) for answer in answers]
        except dns.resolver.NXDOMAIN:
            return None
        except Exception as e:
            raise e

    async def _check_dns_resolution(self, domain: str) -> Dict[str, Any]:
        """Check if domain resolves via DNS"""
        try:
            loop = asyncio.get_event_loop()
            a_records = await loop.run_in_executor(
                self.thread_pool,
                self._resolve_dns_cached,
                domain
            )

            if a_records:
                return {
                    "resolvable": True,
                    "a_records": a_records,
                    "reason": "Domain resolves to IP addresses"
                }
            else:
                return {
                    "resolvable": False,
                    "reason": "Domain does not resolve (NXDOMAIN)"
                }

        except Exception as e:
            raise  # Let retry logic handle it

# Initialize domain checker
domain_checker = DomainChecker()

@mcp.tool()
async def check_domain(domain: str) -> str:
    """Check if a single domain name is available for registration"""
    result = await domain_checker.check_domain_availability(domain)
    
    # Format the response nicely
    if result["available"] is True:
        status = "✅ LIKELY AVAILABLE"
    elif result["available"] is False:
        status = "❌ NOT AVAILABLE"
    else:
        status = "❓ UNCLEAR"
    
    response = f"""Domain: {domain}
Status: {status}

WHOIS Check: {'Available' if result['whois_available'] else 'Registered' if result['whois_available'] is False else 'Unclear'}
DNS Resolution: {'Not resolving' if result['dns_resolvable'] is False else 'Resolving' if result['dns_resolvable'] else 'Error'}

Details:
{json.dumps(result['details'], indent=2)}
"""
    
    if result["error"]:
        response += f"\nError: {result['error']}"
    
    return response

@mcp.tool()
async def check_multiple_domains(
    domains: List[str],
    skip_whois: bool = False,
    batch_size: int = BATCH_SIZE
) -> str:
    """
    Check availability for multiple domain names at once (optimized for large batches)

    Args:
        domains: List of domain names to check
        skip_whois: Skip WHOIS checks for faster results (DNS-only mode, recommended for 10k+ domains)
        batch_size: Process domains in batches (default 1000)
    """
    if not domains:
        return "Error: Domain list is required"

    total_domains = len(domains)
    logger.info(f"Starting check for {total_domains} domains (skip_whois={skip_whois}, batch_size={batch_size})")

    start_time = time.time()
    all_results = []

    # Process domains in batches to avoid memory issues
    for batch_num, i in enumerate(range(0, total_domains, batch_size)):
        batch = domains[i:i + batch_size]
        batch_start = time.time()

        logger.info(f"Processing batch {batch_num + 1}/{(total_domains + batch_size - 1) // batch_size} "
                   f"({len(batch)} domains)")

        # Check domains in batch concurrently (semaphores limit actual concurrency)
        tasks = [
            domain_checker.check_domain_availability(domain, skip_whois=skip_whois)
            for domain in batch
        ]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions in the results
        for j, result in enumerate(batch_results):
            if isinstance(result, Exception):
                all_results.append({
                    "domain": batch[j],
                    "available": None,
                    "error": str(result)
                })
            else:
                all_results.append(result)

        batch_elapsed = time.time() - batch_start
        logger.info(f"Batch {batch_num + 1} completed in {batch_elapsed:.2f}s "
                   f"({len(batch) / batch_elapsed:.1f} domains/sec)")

    elapsed = time.time() - start_time

    # Format results as a summary table
    response = f"Domain Availability Check Results ({total_domains} domains)\n"
    response += f"{'=' * 60}\n\n"
    response += f"Mode: {'DNS-only (fast)' if skip_whois else 'DNS + WHOIS (thorough)'}\n"
    response += f"Total time: {elapsed:.2f}s ({total_domains / elapsed:.1f} domains/sec)\n"
    response += f"Statistics: {domain_checker.stats}\n\n"

    # Show summary counts
    available_count = sum(1 for r in all_results if r.get("available") is True)
    unavailable_count = sum(1 for r in all_results if r.get("available") is False)
    unclear_count = sum(1 for r in all_results if r.get("available") is None)

    response += f"Available: {available_count}, Unavailable: {unavailable_count}, Unclear: {unclear_count}\n\n"

    # Show first 50 results in table format
    display_limit = min(50, len(all_results))
    response += f"First {display_limit} results:\n"
    for result in all_results[:display_limit]:
        if result["available"] is True:
            status = "✅ AVAILABLE"
        elif result["available"] is False:
            status = "❌ UNAVAILABLE"
        else:
            status = "❓ UNCLEAR"

        response += f"  {result['domain']:<40} {status}\n"

    if len(all_results) > display_limit:
        response += f"\n... and {len(all_results) - display_limit} more results\n"

    # For smaller lists, include detailed JSON
    if total_domains <= 100:
        response += f"\n\nDetailed results:\n{json.dumps(all_results, indent=2)}"
    else:
        # For large lists, just return summary and available domains
        available_domains = [r["domain"] for r in all_results if r.get("available") is True]
        if available_domains:
            response += f"\n\nAvailable domains ({len(available_domains)}):\n"
            response += "\n".join(f"  - {d}" for d in available_domains[:100])
            if len(available_domains) > 100:
                response += f"\n  ... and {len(available_domains) - 100} more"

    return response

@mcp.resource("domain://check/{domain}")
async def domain_info_resource(domain: str) -> str:
    """Get domain availability information as a resource"""
    result = await domain_checker.check_domain_availability(domain)
    return json.dumps(result, indent=2)

if __name__ == "__main__":
    mcp.run(transport="stdio")