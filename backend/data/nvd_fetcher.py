"""
NVD (National Vulnerability Database) Data Fetcher
Pulls CVE data from the NVD API and stores locally for ML training.
"""
import httpx
import asyncio
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NVDFetcher:
    """Fetches CVE data from the National Vulnerability Database API."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RESULTS_PER_PAGE = 100
    
    def __init__(self, api_key: Optional[str] = None, data_dir: str = "./data"):
        self.api_key = api_key
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Rate limiting: 5 requests/30s without key, 50 requests/30s with key
        self.request_delay = 0.6 if api_key else 6.0
    
    async def fetch_cves(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        days_back: int = 7,
        max_results: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch CVEs from NVD API.
        
        Args:
            start_date: Start of date range (defaults to days_back from now)
            end_date: End of date range (defaults to now)
            days_back: Number of days to look back if start_date not provided
            max_results: Maximum number of CVEs to fetch (None = all)
            
        Returns:
            List of CVE records
        """
        if not 1 <= days_back <= 120 or (max_results is not None and max_results < 1):
            raise ValueError('days_back must be 1..120 and max_results must be positive')
        if end_date is None:
            end_date = datetime.now()
        if start_date is None:
            start_date = end_date - timedelta(days=days_back)
        
        logger.info(f"Fetching CVEs from {start_date.date()} to {end_date.date()}")
        
        all_cves = []
        start_index = 0
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            while True:
                params = {
                    "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                    "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                    "startIndex": start_index,
                    "resultsPerPage": self.RESULTS_PER_PAGE
                }
                
                headers = {}
                if self.api_key:
                    headers["apiKey"] = self.api_key
                
                try:
                    response = await client.get(
                        self.BASE_URL,
                        params=params,
                        headers=headers
                    )
                    response.raise_for_status()
                    data = response.json()
                    
                    vulnerabilities = data.get("vulnerabilities", [])
                    total_results = data.get("totalResults", 0)
                    
                    for vuln in vulnerabilities:
                        cve = self._parse_cve(vuln.get("cve", {}))
                        if cve:
                            all_cves.append(cve)
                    
                    logger.info(f"Fetched {len(all_cves)}/{total_results} CVEs")
                    
                    if max_results is not None and len(all_cves) >= max_results:
                        all_cves = all_cves[:max_results]
                        break

                    # Check if we have all results
                    if start_index + self.RESULTS_PER_PAGE >= total_results:
                        break
                    
                    # Check max_results limit
                    if max_results and len(all_cves) >= max_results:
                        all_cves = all_cves[:max_results]
                        break
                    
                    start_index += self.RESULTS_PER_PAGE
                    await asyncio.sleep(self.request_delay)
                    
                except httpx.HTTPError as e:
                    raise RuntimeError("NVD fetch failed; partial data was not saved") from e
                except Exception as e:
                    raise RuntimeError("Invalid NVD response; partial data was not saved") from e
        
        logger.info(f"Total CVEs fetched: {len(all_cves)}")
        return all_cves
    
    def _parse_cve(self, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a CVE record into a normalized format."""
        try:
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None
            
            # Get descriptions (prefer English)
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Get CVSS metrics (prefer v3.1, fallback to v3.0, then v2.0)
            metrics = cve_data.get("metrics", {})
            cvss_data = self._extract_cvss(metrics)
            
            # Get CWE (weakness enumeration)
            weaknesses = cve_data.get("weaknesses", [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_ids.append(desc.get("value", ""))
            
            # Get references
            references = cve_data.get("references", [])
            ref_urls = [ref.get("url", "") for ref in references]
            ref_tags = []
            for ref in references:
                ref_tags.extend(ref.get("tags", []))
            
            # Get configurations (affected products)
            configurations = cve_data.get("configurations", [])
            affected_products = self._count_affected_products(configurations)
            
            # Dates
            published = cve_data.get("published", "")
            last_modified = cve_data.get("lastModified", "")
            
            return {
                "cve_id": cve_id,
                "description": description,
                "published": published,
                "last_modified": last_modified,
                "cvss_base_score": cvss_data.get("base_score"),
                "cvss_exploitability_score": cvss_data.get("exploitability_score"),
                "cvss_impact_score": cvss_data.get("impact_score"),
                "cvss_version": cvss_data.get("version"),
                "attack_vector": cvss_data.get("attack_vector"),
                "attack_complexity": cvss_data.get("attack_complexity"),
                "privileges_required": cvss_data.get("privileges_required"),
                "user_interaction": cvss_data.get("user_interaction"),
                "scope": cvss_data.get("scope"),
                "confidentiality_impact": cvss_data.get("confidentiality_impact"),
                "integrity_impact": cvss_data.get("integrity_impact"),
                "availability_impact": cvss_data.get("availability_impact"),
                "cwe_ids": cwe_ids,
                "reference_count": len(ref_urls),
                "reference_tags": list(set(ref_tags)),
                "affected_product_count": affected_products,
                "has_patch": "Patch" in ref_tags,
                "has_exploit": "Exploit" in ref_tags,
            }
        except Exception as e:
            logger.warning(f"Error parsing CVE: {e}")
            return None
    
    def _extract_cvss(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CVSS data, preferring newer versions."""
        # Try CVSS 3.1
        if metrics.get("cvssMetricV31"):
            metric = metrics["cvssMetricV31"][0]
            cvss = metric.get("cvssData", {})
            return {
                "version": "3.1",
                "base_score": cvss.get("baseScore"),
                "exploitability_score": metric.get("exploitabilityScore"),
                "impact_score": metric.get("impactScore"),
                "attack_vector": cvss.get("attackVector"),
                "attack_complexity": cvss.get("attackComplexity"),
                "privileges_required": cvss.get("privilegesRequired"),
                "user_interaction": cvss.get("userInteraction"),
                "scope": cvss.get("scope"),
                "confidentiality_impact": cvss.get("confidentialityImpact"),
                "integrity_impact": cvss.get("integrityImpact"),
                "availability_impact": cvss.get("availabilityImpact"),
            }
        
        # Try CVSS 3.0
        if metrics.get("cvssMetricV30"):
            metric = metrics["cvssMetricV30"][0]
            cvss = metric.get("cvssData", {})
            return {
                "version": "3.0",
                "base_score": cvss.get("baseScore"),
                "exploitability_score": metric.get("exploitabilityScore"),
                "impact_score": metric.get("impactScore"),
                "attack_vector": cvss.get("attackVector"),
                "attack_complexity": cvss.get("attackComplexity"),
                "privileges_required": cvss.get("privilegesRequired"),
                "user_interaction": cvss.get("userInteraction"),
                "scope": cvss.get("scope"),
                "confidentiality_impact": cvss.get("confidentialityImpact"),
                "integrity_impact": cvss.get("integrityImpact"),
                "availability_impact": cvss.get("availabilityImpact"),
            }
        
        # Fallback to CVSS 2.0
        if metrics.get("cvssMetricV2"):
            metric = metrics["cvssMetricV2"][0]
            cvss = metric.get("cvssData", {})
            return {
                "version": "2.0",
                "base_score": cvss.get("baseScore"),
                "exploitability_score": metric.get("exploitabilityScore"),
                "impact_score": metric.get("impactScore"),
                "attack_vector": cvss.get("accessVector"),
                "attack_complexity": cvss.get("accessComplexity"),
                "privileges_required": None,
                "user_interaction": None,
                "scope": None,
                "confidentiality_impact": cvss.get("confidentialityImpact"),
                "integrity_impact": cvss.get("integrityImpact"),
                "availability_impact": cvss.get("availabilityImpact"),
            }
        
        return {}
    
    def _count_affected_products(self, configurations: List[Dict]) -> int:
        """Count the number of affected products/versions."""
        count = 0
        for config in configurations:
            for node in config.get("nodes", []):
                count += len(node.get("cpeMatch", []))
        return count
    
    async def save_to_json(self, cves: List[Dict], filename: str = "cves.json"):
        """Save CVE data to JSON file."""
        filepath = self.data_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({
                "fetched_at": datetime.now().isoformat(),
                "count": len(cves),
                "cves": cves
            }, f, indent=2, default=str)
        logger.info(f"Saved {len(cves)} CVEs to {filepath}")
    
    def load_from_json(self, filename: str = "cves.json") -> List[Dict]:
        """Load CVE data from JSON file."""
        filepath = self.data_dir / filename
        if not filepath.exists():
            logger.warning(f"No data file found at {filepath}")
            return []
        
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        cves = data.get("cves", [])
        logger.info(f"Loaded {len(cves)} CVEs from {filepath}")
        return cves


# CLI entry point
if __name__ == "__main__":
    import argparse
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Fetch CVE data from NVD")
    parser.add_argument("--days", type=int, default=7, help="Days of history to fetch")
    parser.add_argument("--max", type=int, default=None, help="Maximum CVEs to fetch")
    parser.add_argument("--output", type=str, default="cves.json", help="Output filename")
    args = parser.parse_args()
    
    fetcher = NVDFetcher(
        api_key=os.getenv("NVD_API_KEY"),
        data_dir="./data"
    )
    
    async def main():
        cves = await fetcher.fetch_cves(days_back=args.days, max_results=args.max)
        if not cves:
            raise RuntimeError('NVD returned no usable CVEs')
        await fetcher.save_to_json(cves, args.output)
    
    asyncio.run(main())
