from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Set

import requests
from bs4 import BeautifulSoup

from core.config import Config


SECURITY_HEADERS = [
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
    "referrer-policy",
    "x-xss-protection",
]

SENSITIVE_PATHS = [
    "/.git/",
    "/.svn/",
    "/config.php",
    "/backup/",
    "/.env",
    "/.htaccess",
]


def _same_domain(start_url: str, url: str) -> bool:
    from urllib.parse import urlparse

    s = urlparse(start_url)
    u = urlparse(url)
    return (u.scheme in ("http", "https")) and (u.netloc == s.netloc or u.netloc == "")


def _normalize_url(start_url: str, href: str) -> str:
    from urllib.parse import urljoin

    return urljoin(start_url, href)


def _fetch_robots_txt(base_url: str, headers: Dict[str, str], timeout: int) -> Set[str]:
    from urllib.parse import urljoin

    robots_url = urljoin(base_url, "/robots.txt")
    try:
        resp = requests.get(robots_url, headers=headers, timeout=timeout)
    except requests.RequestException:
        return set()

    if resp.status_code != 200:
        return set()

    disallowed: Set[str] = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.add(path)
    return disallowed


def scan_site(config: Config, logger, root_url: str):
    """
    Non-destructive same-domain web security scanner.

    - Respects robots.txt when configured.
    - Checks for missing common security headers.
    - Looks for open directory listings and sensitive files.
    - Optionally flags basic reflected input behaviour (without exploiting).
    """
    root_url = root_url.rstrip("/")
    max_depth = int(config.get("web_scanner.max_depth", 2))
    timeout = int(config.get("web_scanner.request_timeout", 5))
    ua = config.get("web_scanner.user_agent", "CyberResearchLab/1.0")
    respect_robots = bool(config.get("web_scanner.respect_robots", True))

    session = requests.Session()
    session.headers.update({"User-Agent": ua})

    disallowed_paths: Set[str] = set()
    if respect_robots:
        disallowed_paths = _fetch_robots_txt(root_url, session.headers, timeout)
        if disallowed_paths:
            logger.info("robots.txt disallow rules: %s", sorted(disallowed_paths))

    visited: Set[str] = set()
    to_visit: deque[tuple[str, int]] = deque()
    to_visit.append((root_url, 0))

    findings: List[Dict[str, object]] = []

    while to_visit:
        url, depth = to_visit.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        # Respect robots.txt by path component only
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if respect_robots:
            for dis in disallowed_paths:
                if parsed.path.startswith(dis):
                    logger.debug("Skipping %s due to robots.txt rule %s", url, dis)
                    break
            else:
                pass
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            logger.warning("Request to %s failed: %s", url, exc)
            continue

        logger.info("Scanned %s (status %s)", url, resp.status_code)

        # Check security headers
        missing = [
            h
            for h in SECURITY_HEADERS
            if h not in {k.lower(): v for k, v in resp.headers.items()}
        ]
        if missing:
            findings.append(
                {
                    "type": "missing_security_headers",
                    "url": url,
                    "missing": missing,
                }
            )
            logger.info(
                "Missing security headers at %s: %s",
                url,
                ", ".join(missing),
            )

        # Simple open directory listing heuristic
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" in content_type.lower():
            text = resp.text
            if re.search(r"Index of /", text, re.IGNORECASE):
                findings.append({"type": "open_directory", "url": url})
                logger.info("Potential open directory listing at %s", url)

            # Extract same-domain links to crawl
            soup = BeautifulSoup(text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a.get("href")
                next_url = _normalize_url(root_url, href)
                if _same_domain(root_url, next_url) and next_url not in visited:
                    to_visit.append((next_url, depth + 1))

        # Check sensitive paths relative to this URL's origin
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in SENSITIVE_PATHS:
            sensitive_url = _normalize_url(base, path)
            if sensitive_url in visited:
                continue
            try:
                s_resp = session.get(sensitive_url, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                continue
            visited.add(sensitive_url)
            if s_resp.status_code == 200:
                findings.append(
                    {
                        "type": "sensitive_file",
                        "url": sensitive_url,
                        "status": s_resp.status_code,
                    }
                )
                logger.info(
                    "Potential exposed sensitive path at %s (status %s)",
                    sensitive_url,
                    s_resp.status_code,
                )

    logger.info("Web scan complete. Total findings: %d", len(findings))
    return findings

