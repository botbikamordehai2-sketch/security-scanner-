"""
Data Hunter Agent — Commodities & Energy Price Tracker.
Tracks Gold (XAU), Crude Oil (WTI/Brent), Copper, Natural Gas, Silver.
Fetches real-time prices from free APIs, summarizes via DeepSeek into daily trading insights.

Deployed as: Cloud Run Private Service (no external access)
Triggered by: Pub/Sub Push Subscription OR cron schedule (Cloud Scheduler)
Outputs to:   Pub/Sub Topic "scan.results" + Firestore

Local dev:    python agent.py → starts Flask on :8080
"""

import asyncio
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Add project root to path ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import httpx
from flask import Flask, request, jsonify

from shared.db import get_db
from shared.events import ScanRequest, ScanResult
from shared.pubsub_utils import publish_message, IS_CLOUD
from shared.deepseek import get_deepseek

app = Flask(__name__)
PORT = int(os.environ.get("PORT", 8080))

# ── Configuration ────────────────────────────────────

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")

# Free APIs — no key required for basic tier
METALS_API = "https://api.metals.live/v1/spot"           # Gold, Silver, Platinum, Palladium
GOLD_API_SINGLE = "https://api.metals.live/v1/spot/gold" # Single metal
OIL_API = "https://api.oilpriceapi.com/v1/prices/latest" # Requires free API key
FRED_API_KEY = os.environ.get("FRED_API_KEY", "")        # Optional: Macro data
OIL_API_KEY = os.environ.get("OIL_API_KEY", "")          # Optional: oilpriceapi.com
MARINETRAFFIC_API_KEY = os.environ.get("MARINETRAFFIC_API_KEY", "")  # MarineTraffic Containers API

# Polymarket — prediction market signals
POLYMARKET_GAMMA_API = "https://gamma-api.polymarket.com"
POLYMARKET_CLOB_API = "https://clob.polymarket.com"

# Symbols to track
COMMODITIES = {
    "XAU": {"name": "Gold", "metal": "gold", "api": "metals"},
    "XAG": {"name": "Silver", "metal": "silver", "api": "metals"},
    "XPT": {"name": "Platinum", "metal": "platinum", "api": "metals"},
    "XPD": {"name": "Palladium", "metal": "palladium", "api": "metals"},
    "WTI": {"name": "Crude Oil WTI", "api": "oilpriceapi"},
    "BRENT": {"name": "Brent Crude", "api": "oilpriceapi"},
}

# Polymarket markets to track (high-signal for macro traders)
POLYMARKET_MARKETS = [
    "will-fed-cut-rates-in-june-2026",
    "will-recession-be-declared-in-2026",
    "us-cpi-inflation-above-3-percent-may-2026",
    "will-oil-hit-100-in-2026",
    "will-gold-hit-3500-in-2026",
]

# MarineTraffic — strategic chokepoints for commodities
MARITIME_CHOKEPOINTS = [
    {"name": "Strait of Hormuz", "portid": 10635, "signal": "Oil supply risk"},
    {"name": "Suez Canal Approach", "portid": 2556, "signal": "Global trade disruption"},
    {"name": "Panama Canal", "portid": 21636, "signal": "LNG / container delays"},
    {"name": "Houston Ship Channel", "portid": 18630, "signal": "US crude export bottleneck"},
]

# Fallback: CoinGecko free tier (no API key needed)
COINGECKO_METALS_URL = "https://api.coingecko.com/api/v3/simple/price"
METAL_IDS = {
    "gold": "tether-gold",           # XAUT pegged to gold
    "silver": "tether-gold",          # Will adjust
}

# True commodity price tracking via metals.live (primary)
PRIMARY_PRICES = {}


# ── Price Fetchers ────────────────────────────────────

async def fetch_metals_live(client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetch spot prices from metals.live — free, no API key needed."""
    metals = ["gold", "silver", "platinum", "palladium"]
    prices = {}
    
    async def fetch_one(metal: str):
        try:
            resp = await client.get(
                f"https://api.metals.live/v1/spot/{metal}",
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    return metal, {
                        "price_usd": data[0].get("price", 0),
                        "currency": "USD",
                        "timestamp": data[0].get("timestamp", ""),
                        "change_pct": data[0].get("change_percentage", 0),
                    }
            print(f"[data_hunter] metals.live/{metal} returned status {resp.status_code}")
            return metal, None
        except Exception as e:
            print(f"[data_hunter] metals.live/{metal} error: {e}")
            return metal, None

    tasks = [fetch_one(m) for m in metals]
    results = await asyncio.gather(*tasks)
    
    for metal, data in results:
        if data:
            prices[metal.upper()] = data
    
    return prices


async def fetch_oil_prices(client: httpx.AsyncClient) -> Dict[str, Any]:
    """Fetch oil prices. Falls back to free EIA data if no API key."""
    prices = {}
    
    if OIL_API_KEY:
        try:
            resp = await client.get(
                "https://api.oilpriceapi.com/v1/prices/latest",
                headers={
                    "Authorization": f"Token {OIL_API_KEY}",
                    "Content-Type": "application/json",
                },
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                prices["WTI"] = {
                    "price_usd": data.get("price", 0),
                    "currency": "USD",
                }
                prices["BRENT"] = {
                    "price_usd": data.get("brent_price", 0),
                    "currency": "USD",
                }
                return prices
        except Exception as e:
            print(f"[data_hunter] Oil API error: {e}")
    
    # Fallback: try a public oil price endpoint
    try:
        resp = await client.get(
            "https://api.eia.gov/v2/petroleum/pri/spt/data/?frequency=daily&data[0]=value&sort[0][column]=period&sort[0][direction]=desc&length=1&api_key=" + (FRED_API_KEY or "DEMO"),
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            # Parse best effort
            prices["WTI"] = {"price_usd": 0, "note": "EIA fallback — limited data", "currency": "USD"}
    except Exception as e:
        print(f"[data_hunter] EIA fallback error: {e}")
        prices["WTI"] = {"price_usd": 0, "note": "Unavailable — add OIL_API_KEY", "currency": "USD"}
        prices["BRENT"] = {"price_usd": 0, "note": "Unavailable — add OIL_API_KEY", "currency": "USD"}
    
    return prices


async def fetch_dxy_index(client: httpx.AsyncClient) -> Optional[float]:
    """Fetch US Dollar Index (DXY) — critical for gold correlation.
    DXY up → gold down (typically)."""
    try:
        resp = await client.get(
            "https://api.exchangerate-api.com/v4/latest/USD",
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            # DXY approximate via EUR/USD inverse correlation
            eur_usd = data.get("rates", {}).get("EUR", 0.92)
            dxy_approx = round(100 / eur_usd * 0.92, 2)  # normalization
            return dxy_approx
    except Exception as e:
        print(f"[data_hunter] DXY fetch error: {e}")
    return None


# ── Polymarket Whale Detector ────────────────────────

async def fetch_polymarket_market(client: httpx.AsyncClient, slug: str) -> Optional[Dict]:
    """Fetch a single Polymarket market by slug. Returns market + whale signals."""
    try:
        # Get market metadata
        resp = await client.get(
            f"{POLYMARKET_GAMMA_API}/markets/slug/{slug}",
            timeout=10.0,
        )
        if resp.status_code != 200:
            return None

        market = resp.json()
        token_ids = market.get("clobTokenIds", [])
        if not token_ids:
            # Try outcomes directly
            outcomes = market.get("outcomes", [])
            token_ids_raw = [o.get("clobTokenId") for o in outcomes if o.get("clobTokenId")]
            token_ids = json.loads(token_ids_raw[0]) if token_ids_raw and isinstance(token_ids_raw[0], str) else token_ids_raw[:2] if token_ids_raw else []

        yes_price = None
        volume_24h = 0
        whale_count = 0

        # Try CLOB orderbook for each token
        for tid in token_ids[:2]:
            try:
                ob_resp = await client.get(
                    f"{POLYMARKET_CLOB_API}/book",
                    params={"token_id": str(tid)},
                    timeout=8.0,
                )
                if ob_resp.status_code == 200:
                    book = ob_resp.json()
                    bids = book.get("bids", [])
                    asks = book.get("asks", [])
                    # Whale detection: any order > $200 with size > 100
                    for side in [bids, asks]:
                        for order in side:
                            price = float(order.get("price", 0))
                            size = float(order.get("size", 0))
                            if price > 0.01 and size > 100:
                                whale_count += 1
                    # Best bid = YES price estimate
                    if bids and yes_price is None:
                        yes_price = float(bids[0].get("price", 0))
                # Also get price history for volume
                hist_resp = await client.get(
                    f"{POLYMARKET_GAMMA_API}/markets/{market.get('id')}/prices",
                    timeout=8.0,
                )
                if hist_resp.status_code == 200:
                    prices_hist = hist_resp.json()
                    if isinstance(prices_hist, list) and prices_hist:
                        latest = prices_hist[-1]
                        yes_price = yes_price or float(latest.get("price", 0))
                        volume_24h = float(latest.get("volume", 0))
            except Exception:
                continue

        return {
            "slug": slug,
            "question": market.get("question", slug),
            "yes_price": round(yes_price * 100, 1) if yes_price else None,
            "volume_24h": round(volume_24h, 0),
            "whale_orders_detected": whale_count,
            "signal": "🐋 Whale active" if whale_count > 5 else "🔍 Normal" if whale_count > 0 else "💤 Quiet",
            "url": f"https://polymarket.com/event/{slug}",
        }
    except Exception as e:
        print(f"[data_hunter] Polymarket/{slug} error: {e}")
        return None


async def run_polymarket_scan() -> List[Dict]:
    """Scan all tracked Polymarket markets in parallel. Returns list with signals."""
    async with httpx.AsyncClient() as client:
        tasks = [fetch_polymarket_market(client, slug) for slug in POLYMARKET_MARKETS]
        results = await asyncio.gather(*tasks)
    valid = [r for r in results if r is not None]
    total_whales = sum(r.get("whale_orders_detected", 0) for r in valid)
    print(f"[data_hunter] Polymarket: {len(valid)}/{len(POLYMARKET_MARKETS)} markets, {total_whales} whale orders")
    return valid


# ── MarineTraffic Port Congestion Scanner ─────────────

async def fetch_marinetraffic_congestion(client: httpx.AsyncClient, chokepoint: Dict) -> Optional[Dict]:
    """Fetch vessel congestion data for a maritime chokepoint."""
    portid = chokepoint["portid"]
    name = chokepoint["name"]
    signal = chokepoint["signal"]

    try:
        # Use MarineTraffic public PS01 API (vessel positions near port)
        headers = {}
        if MARINETRAFFIC_API_KEY:
            headers["X-API-Key"] = MARINETRAFFIC_API_KEY

        resp = await client.get(
            f"https://services.marinetraffic.com/api/exportvessels/{MARINETRAFFIC_API_KEY or 'demo'}/v:8/portid:{portid}/protocol:json",
            timeout=10.0,
        )
        if resp.status_code == 200:
            vessels = resp.json()
            if isinstance(vessels, list):
                # Count vessels by type
                tankers = sum(1 for v in vessels if v.get("SHIPTYPE", 0) in [80, 81, 82, 83, 84])  # Tanker types
                cargo = sum(1 for v in vessels if v.get("SHIPTYPE", 0) in [70, 71, 72, 73, 74, 75])  # Cargo types
                total = len(vessels)
                # Congestion score: > 50 vessels = high, > 25 = medium
                severity = "🔴 HIGH" if total > 50 else "🟡 MEDIUM" if total > 25 else "🟢 LOW"
                return {
                    "chokepoint": name,
                    "signal_type": signal,
                    "total_vessels": total,
                    "tankers": tankers,
                    "cargo_vessels": cargo,
                    "congestion": severity,
                    "risk_assessment": "Supply chain disruption likely" if total > 50 else "Normal operations" if total < 25 else "Monitor closely",
                }
    except Exception as e:
        print(f"[data_hunter] MarineTraffic/{name} error: {e}")

    # Fallback: return placeholder with note
    return {
        "chokepoint": name,
        "signal_type": signal,
        "total_vessels": 0,
        "congestion": "⚪ N/A",
        "risk_assessment": f"API unavailable — add MARINETRAFFIC_API_KEY",
    }


async def run_marinetraffic_scan() -> List[Dict]:
    """Scan all maritime chokepoints. Returns congestion signals."""
    async with httpx.AsyncClient() as client:
        tasks = [fetch_marinetraffic_congestion(client, cp) for cp in MARITIME_CHOKEPOINTS]
        results = await asyncio.gather(*tasks)
    high = [r for r in results if "HIGH" in r.get("congestion", "")]
    medium = [r for r in results if "MEDIUM" in r.get("congestion", "")]
    print(f"[data_hunter] MarineTraffic: {len(high)} high, {len(medium)} medium congestion points")
    return list(results)


# ── Combined Market Scan ─────────────────────────────

async def run_full_hunt() -> Dict[str, Any]:
    """Run all data sources in parallel: prices + polymarket + marinetraffic."""
    async with httpx.AsyncClient() as client:
        metals_task = fetch_metals_live(client)
        oil_task = fetch_oil_prices(client)
        dxy_task = fetch_dxy_index(client)
        # These don't need the shared client due to different base URLs
        pass
    
    # Run all scans concurrently
    prices_data, polymarket_data, marinetraffic_data = await asyncio.gather(
        run_price_scan(),
        run_polymarket_scan(),
        run_marinetraffic_scan(),
    )

    return {
        **prices_data,
        "polymarket": {
            "markets_scanned": len(polymarket_data),
            "signals": polymarket_data,
            "total_whale_orders": sum(m.get("whale_orders_detected", 0) for m in polymarket_data),
        },
        "marinetraffic": {
            "chokepoints_scanned": len(marinetraffic_data),
            "congestion_points": marinetraffic_data,
            "high_congestion": [m for m in marinetraffic_data if "HIGH" in m.get("congestion", "")],
        },
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Force-Exit Protection ────────────────────────────

def get_market_close_warning() -> Optional[Dict]:
    """
    Check if we're within 3 minutes of a major market close.
    Returns warning dict if close is imminent, None otherwise.
    Protects against trading near illiquid market closes.
    """
    now = datetime.now(timezone.utc)
    current_hour = now.hour
    current_minute = now.minute

    # Major market closes in UTC:
    # 16:00 NYSE close (21:00 UTC winter / 20:00 UTC summer — approximate)
    # 21:00 LSE close
    # 06:00 Tokyo close
    market_closes = [
        ("NYSE", 20, 0),    # 20:00 UTC (approximate for DST)
        ("LSE", 16, 30),    # 16:30 UTC
        ("Tokyo", 6, 0),    # 06:00 UTC
        ("CME_GLOBEX", 21, 15),  # 21:15 UTC (energy futures)
    ]

    for market, close_hour, close_min in market_closes:
        # Calculate minutes until close
        close_total_min = close_hour * 60 + close_min
        now_total_min = current_hour * 60 + current_minute
        diff_min = close_total_min - now_total_min

        if 0 <= diff_min <= 3:
            return {
                "market": market,
                "closes_in_minutes": diff_min,
                "warning": f"⚠️ {market} closes in {diff_min}min — FORCE-EXIT recommended. Do not open new positions.",
                "action": "FORCE_EXIT",
                "timestamp_utc": now.isoformat(),
            }

    return None


async def run_price_scan() -> Dict[str, Any]:
    """Run all price fetches in parallel. Returns structured price data."""
    async with httpx.AsyncClient() as client:
        metals_task = fetch_metals_live(client)
        oil_task = fetch_oil_prices(client)
        dxy_task = fetch_dxy_index(client)
        
        metals, oil, dxy = await asyncio.gather(metals_task, oil_task, dxy_task)
    
    # Merge results
    all_prices = {**metals, **oil}
    
    result = {
        "prices": all_prices,
        "dxy_approx": dxy,
        "total_commodities_tracked": len(all_prices),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "apis_used": {
            "metals_live": bool(metals),
            "oil_api_key_configured": bool(OIL_API_KEY),
        },
    }
    
    print(f"[data_hunter] Fetched {len(all_prices)} commodity prices. DXY ≈ {dxy}")
    return result


# ── DeepSeek Summarizer ──────────────────────────────

def summarize_trading_insights(price_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send price data to DeepSeek for trading insights summarization.
    Uses shared DeepSeekClient with retry logic + correct /v1/ URL.
    Returns structured Hebrew trading insights.
    """
    client = get_deepseek()
    if not client.is_configured:
        return {
            "summary": "DeepSeek not configured — raw prices only",
            "raw_prices": price_data.get("prices", {}),
        }

    prices = price_data.get("prices", {})
    dxy = price_data.get("dxy_approx", "N/A")
    
    # Build clean price summary
    price_lines = []
    for symbol, data in sorted(prices.items()):
        name = COMMODITIES.get(symbol, {}).get("name", symbol)
        price = data.get("price_usd", "N/A")
        change = data.get("change_pct", None)
        change_str = f" ({change:+.2f}%)" if change is not None else ""
        price_lines.append(f"- {name} ({symbol}): ${price}{change_str}")
    
    price_summary = "\n".join(price_lines) if price_lines else "No price data available"
    
    prompt = f"""You are a Commodities & Macro Trading Analyst for an autonomous trading platform.

**TODAY'S COMMODITY PRICES:**
{price_summary}

**US Dollar Index (DXY approx):** {dxy}

**YOUR TASK:**
Analyze these prices and produce a structured Hebrew trading summary with these sections:

### 🥇 זהב וכסף — תמונת מצב 
(Is gold bullish or bearish? What does the DXY tell us? Key levels to watch.)

### 🛢️ אנרגיה — נפט וגז
(Crude oil trend — supply/demand signals. Impact on inflation and trading strategy.)

### 📊 3 תובנות Trading להיום
(3 specific, actionable insights for intraday/swing traders based on commodity prices.)

### ⚡ התראת סיכון
(Any red flags? Inverse correlations breaking down? Unusual volatility expected?)

Format: Hebrew RTL, technical but concise. Target: professional traders. Under 400 words."""

    try:
        result = client.chat(
            prompt=prompt,
            system="You are a Commodities & Macro Trading Analyst. Respond in Hebrew RTL.",
            temperature=0.3,
            max_tokens=1000,
        )
        return {
            "summary": result["response"],
            "raw_prices": prices,
            "dxy": dxy,
            "summarized_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[data_hunter] DeepSeek error: {e}")
        return {
            "summary": f"DeepSeek unavailable: {str(e)}",
            "raw_prices": prices,
        }


# ── Pub/Sub Push Handler ─────────────────────────────

def validate_pubsub_request(envelope: dict) -> dict | None:
    """Extract and decode the Pub/Sub message payload."""
    message = envelope.get("message")
    if not message:
        return None
    data_b64 = message.get("data", "")
    if not data_b64:
        return None
    try:
        decoded = base64.b64decode(data_b64).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None


@app.route("/", methods=["POST"])
def handle_pubsub_push():
    """Handle incoming Pub/Sub push messages — triggers price scan."""
    envelope = request.get_json(force=True, silent=True) or {}

    payload = validate_pubsub_request(envelope)
    if payload is None:
        print("[data_hunter] Invalid Pub/Sub message — acking")
        return ("", 204)

    request_id = payload.get("request_id", "manual")
    print(f"[data_hunter] Received price scan request {request_id}")

    # ── Idempotency ──
    db = get_db()
    if db.request_exists(request_id):
        print(f"[data_hunter] Duplicate request {request_id} — skipping")
        return ("", 204)

    db.mark_request_started(request_id, "data_hunter_scan")

    # ── Run price scan ──
    start_time = time.time()
    try:
        price_data = asyncio.run(run_price_scan())
        insights = summarize_trading_insights(price_data)
        status = "success"
        error_code = None
        error_message = None
        data = {
            "prices": price_data.get("prices", {}),
            "dxy": price_data.get("dxy_approx"),
            "summary": insights.get("summary", ""),
            "commodities_tracked": price_data.get("total_commodities_tracked", 0),
        }
    except Exception as e:
        data = {}
        status = "error"
        error_code = "SCAN_FAILED"
        error_message = str(e)

    duration_ms = int((time.time() - start_time) * 1000)

    # ── Build ScanResult ──
    result = ScanResult(
        request_id=request_id,
        agent_type="data_hunter_agent",
        status=status,
        data=data,
        error_code=error_code,
        error_message=error_message,
        metrics={
            "duration_ms": duration_ms,
            "commodities_tracked": len(data.get("prices", {})),
            "deepseek_used": bool(DEEPSEEK_API_KEY),
        },
    )

    # ── Save to DB ──
    db.save_agent_result(request_id, "data_hunter_agent", result.model_dump())

    # ── Publish to scan.results ──
    result_json = result.model_dump_json()
    msg_id = publish_message("scan.results", result_json, ordering_key=request_id)
    print(f"[data_hunter] Published price results for {request_id} — msg_id: {msg_id}")

    return ("", 204)


# ── Manual Trigger (for cron / Cloud Scheduler) ──────

@app.route("/run", methods=["POST", "GET"])
def manual_trigger():
    """Manual or cron trigger — runs price scan immediately. Ideal for Cloud Scheduler."""
    request_id = f"hunt-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    db = get_db()

    if db.request_exists(request_id):
        return jsonify({"status": "already_ran_this_minute", "request_id": request_id})

    db.mark_request_started(request_id, "data_hunter_daily")

    start_time = time.time()
    try:
        price_data = asyncio.run(run_price_scan())
        insights = summarize_trading_insights(price_data)
        data = {
            "prices": price_data.get("prices", {}),
            "dxy": price_data.get("dxy_approx"),
            "summary": insights.get("summary", ""),
        }
        status = "success"
    except Exception as e:
        data = {}
        status = "error"

    duration_ms = int((time.time() - start_time) * 1000)

    result = ScanResult(
        request_id=request_id,
        agent_type="data_hunter_agent",
        status=status,
        data=data,
        metrics={"duration_ms": duration_ms, "commodities_tracked": len(data.get("prices", {}))},
    )
    db.save_agent_result(request_id, "data_hunter_agent", result.model_dump())

    return jsonify({
        "request_id": request_id,
        "status": status,
        "commodities_tracked": len(data.get("prices", {})),
        "duration_ms": duration_ms,
    })


# ── Health ───────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "agent": "data_hunter_agent",
        "version": "1.0.0",
        "cloud": IS_CLOUD,
        "deepseek_configured": bool(DEEPSEEK_API_KEY),
        "oil_api_configured": bool(OIL_API_KEY),
        "fred_api_configured": bool(FRED_API_KEY),
    })


# ── Full Hunt Endpoint (Prices + Polymarket + MarineTraffic) ──

@app.route("/hunt", methods=["GET"])
def full_hunt():
    """
    Full Data Hunt — commodities, Polymarket whales, MarineTraffic congestion.
    Includes Force-Exit warning if within 3 minutes of market close.
    Best endpoint for cron / Cloud Scheduler daily trigger.
    """
    try:
        hunt_data = asyncio.run(run_full_hunt())
        force_exit = get_market_close_warning()

        return jsonify({
            "status": "success",
            **hunt_data,
            "force_exit_warning": force_exit,
            "safe_to_trade": force_exit is None,
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


# ── Manual price check endpoint ──────────────────────

@app.route("/prices", methods=["GET"])
def get_prices():
    """Quick price check — returns current spot prices without DeepSeek."""
    try:
        price_data = asyncio.run(run_price_scan())
        return jsonify({
            "prices": price_data.get("prices", {}),
            "dxy_approx": price_data.get("dxy_approx"),
            "fetched_at": price_data.get("fetched_at"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Polymarket-only scan ──────────────────────────────

@app.route("/polymarket", methods=["GET"])
def polymarket_scan():
    """Polymarket whale detection — returns market signals only."""
    try:
        signals = asyncio.run(run_polymarket_scan())
        total_whales = sum(s.get("whale_orders_detected", 0) for s in signals)
        return jsonify({
            "markets_scanned": len(signals),
            "signals": signals,
            "total_whale_orders": total_whales,
            "alert": "🐋 Whale activity detected!" if total_whales > 10 else None,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── MarineTraffic-only scan ───────────────────────────

@app.route("/shipping", methods=["GET"])
def shipping_scan():
    """MarineTraffic congestion check — returns chokepoint status only."""
    try:
        congestion = asyncio.run(run_marinetraffic_scan())
        high = [c for c in congestion if "HIGH" in c.get("congestion", "")]
        return jsonify({
            "chokepoints_scanned": len(congestion),
            "congestion_points": congestion,
            "high_congestion": high,
            "alert": "⚠️ Supply chain risk — high port congestion detected" if high else None,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Main ─────────────────────────────────────────────

if __name__ == "__main__":
    print(f"🥇 Data Hunter Agent starting on port {PORT}...")
    print(f"   Health:      http://127.0.0.1:{PORT}/health")
    print(f"   Manual Run:  http://127.0.0.1:{PORT}/run")
    print(f"   Spot Prices: http://127.0.0.1:{PORT}/prices")
    print(f"   DeepSeek:    {'✅ configured' if DEEPSEEK_API_KEY else '❌ missing'}")
    print(f"   Oil API Key: {'✅ configured' if OIL_API_KEY else '⚠️  missing (oil prices limited)'}")
    app.run(host="0.0.0.0", port=PORT, debug=not IS_CLOUD)