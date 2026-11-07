import os, tempfile
from sairecon.core.base import BaseModule
from sairecon.utils import dedupe_keep_order, tool_exists


class URLDiscoveryModule(BaseModule):
    name = "url_discovery"
    description = "URL/endpoint discovery — katana (crawl) + gau + waybackurls, gf categorized"
    required_tools = ["katana"]

    def execute(self):
        if not self.guard_required_tools():
            return self.findings

        all_urls, sources_used, sources_skipped = [], [], []
        apex = self.target

        # 1. katana
        for host in self.hosts:
            url = f"https://{host}"
            self.log(f"Crawling {url} with katana...")
            r = self.run(["katana", "-u", url, "-silent", "-jc", "-kf", "all", "-d", "3"], timeout_sec=180)
            found = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            all_urls += found
        sources_used.append({"tool": "katana", "count": len(all_urls)})

        # 2. gau
        if tool_exists("gau"):
            r = self.run(["gau", "--subs", apex], timeout_sec=180)
            found = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            all_urls += found
            sources_used.append({"tool": "gau", "count": len(found)})
        else:
            sources_skipped.append("gau")

        # 3. waybackurls
        if tool_exists("waybackurls"):
            r = self.run(["waybackurls", apex], timeout_sec=180)
            found = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            all_urls += found
            sources_used.append({"tool": "waybackurls", "count": len(found)})
        else:
            sources_skipped.append("waybackurls")

        merged = dedupe_keep_order(all_urls)

        # 4. gf categorisation
        gf_categories = {}
        if tool_exists("gf"):
            for pattern in ["xss", "sqli", "ssrf", "redirect", "idor", "lfi"]:
                r = self.run(["gf", pattern], timeout_sec=60, input_text="\n".join(merged))
                matches = [l.strip() for l in r.stdout.splitlines() if l.strip()]
                if matches:
                    gf_categories[pattern] = matches
        else:
            sources_skipped.append("gf")

        # 5. unfurl parameter extraction
        unique_params = []
        if tool_exists("unfurl"):
            r = self.run(["unfurl", "keys"], timeout_sec=60, input_text="\n".join(merged))
            unique_params = dedupe_keep_order([l.strip() for l in r.stdout.splitlines() if l.strip()])
        else:
            sources_skipped.append("unfurl")

        self.discovered_urls = merged
        self.add_finding(
            title=f"URL/Endpoint Discovery — {len(merged)} unique URLs across {len(self.hosts)} host(s)",
            command="katana + gau + waybackurls (merged/deduped), gf patterns, unfurl params",
            result={
                "total_unique_urls": len(merged),
                "sources_used": sources_used,
                "sources_skipped": sources_skipped,
                "gf_pattern_matches": gf_categories,
                "unique_query_parameters": unique_params,
                "sample_urls": merged[:500],
            },
            severity=None,
        )
        return self.findings
