"""
Analytics service for Meshtastic Mesh Health Web UI
"""

import logging
import time
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


class AnalyticsService:
    """Service for analytics and statistical calculations."""

    # (gateway_id, from_node, hop_count) → (timestamp, data)
    _CACHE: dict[
        tuple[str | None, int | None, int | None], tuple[float, dict[str, Any]]
    ] = {}
    _CACHE_TTL_SEC: int = 300  # 5-minute cache — analytics data can be this stale

    @staticmethod
    def get_analytics_data(
        gateway_id: str | None = None,
        from_node: int | None = None,
        hop_count: int | None = None,
    ) -> dict[str, Any]:
        """Get comprehensive analytics data for the dashboard with simple in-memory caching."""
        from ..database.connection import get_db_connection

        cache_key = (gateway_id, from_node, hop_count)
        now_ts = time.time()

        cached = AnalyticsService._CACHE.get(cache_key)
        if cached and (now_ts - cached[0] < AnalyticsService._CACHE_TTL_SEC):
            return cached[1]

        logger.info(
            "Computing analytics data (cache miss): gateway_id=%s, from_node=%s, hop_count=%s",
            gateway_id,
            from_node,
            hop_count,
        )

        filters: dict[str, Any] = {}
        if gateway_id:
            filters["gateway_id"] = gateway_id
        if from_node:
            filters["from_node"] = from_node
        if hop_count is not None:
            filters["hop_count"] = hop_count

        twenty_four_hours_ago = now_ts - 86400
        seven_days_ago = now_ts - 7 * 86400

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            combined = AnalyticsService._get_combined_packet_stats(
                cursor, filters, twenty_four_hours_ago
            )
            node_stats = AnalyticsService._get_node_activity_statistics(
                cursor, filters, twenty_four_hours_ago
            )
            temporal_stats = AnalyticsService._get_temporal_patterns(
                cursor, filters, twenty_four_hours_ago
            )
            top_nodes = AnalyticsService._get_top_active_nodes(cursor, seven_days_ago)
            packet_types = AnalyticsService._get_packet_type_distribution(
                cursor, filters, twenty_four_hours_ago
            )
            gateway_stats = AnalyticsService._get_gateway_distribution(
                cursor, filters, twenty_four_hours_ago
            )
        finally:
            conn.close()

        result = {
            "packet_statistics": combined["packet_statistics"],
            "node_statistics": node_stats,
            "signal_quality": combined["signal_quality"],
            "temporal_patterns": temporal_stats,
            "top_nodes": top_nodes,
            "packet_types": packet_types,
            "gateway_distribution": gateway_stats,
        }

        AnalyticsService._CACHE[cache_key] = (now_ts, result)
        logger.info("Analytics data computed successfully (cached for %ds)", AnalyticsService._CACHE_TTL_SEC)
        return result

    @staticmethod
    def _build_where(
        filters: dict,
        since_timestamp: float,
        *,
        include_hop_count: bool = False,
        include_from_node: bool = True,
        include_gateway: bool = True,
    ) -> tuple[str, list[Any]]:
        """Return (WHERE clause string, params list) for packet_history queries."""
        conditions: list[str] = ["timestamp >= ?"]
        params: list[Any] = [since_timestamp]

        if include_gateway and filters.get("gateway_id"):
            conditions.append("gateway_id = ?")
            params.append(filters["gateway_id"])

        if include_from_node and filters.get("from_node"):
            conditions.append("from_node_id = ?")
            params.append(filters["from_node"])

        if include_hop_count and filters.get("hop_count") is not None:
            conditions.append("(hop_start - hop_limit) = ?")
            params.append(filters["hop_count"])

        return " AND ".join(conditions), params

    @staticmethod
    def _get_combined_packet_stats(
        cursor: Any, filters: dict, since_timestamp: float
    ) -> dict[str, Any]:
        """Single scan for both packet statistics and signal quality."""
        where_clause, params = AnalyticsService._build_where(
            filters, since_timestamp, include_hop_count=True
        )

        cursor.execute(
            f"""
            SELECT
                COUNT(*) as total_packets,
                SUM(CASE WHEN processed_successfully = 1 THEN 1 ELSE 0 END) as successful_packets,
                AVG(CASE WHEN payload_length IS NOT NULL AND payload_length > 0 THEN payload_length END) as avg_payload_size,
                AVG(CASE WHEN rssi IS NOT NULL AND rssi != 0 THEN rssi END) as avg_rssi,
                AVG(CASE WHEN snr IS NOT NULL THEN snr END) as avg_snr,
                COUNT(CASE WHEN rssi IS NOT NULL AND rssi != 0 THEN 1 END) as rssi_count,
                COUNT(CASE WHEN snr IS NOT NULL THEN 1 END) as snr_count,
                SUM(CASE WHEN rssi IS NOT NULL AND rssi != 0 AND rssi > -70 THEN 1 ELSE 0 END) as rssi_excellent,
                SUM(CASE WHEN rssi > -80 AND rssi <= -70 THEN 1 ELSE 0 END) as rssi_good,
                SUM(CASE WHEN rssi > -90 AND rssi <= -80 THEN 1 ELSE 0 END) as rssi_fair,
                SUM(CASE WHEN rssi IS NOT NULL AND rssi != 0 AND rssi <= -90 THEN 1 ELSE 0 END) as rssi_poor,
                SUM(CASE WHEN snr IS NOT NULL AND snr > 10 THEN 1 ELSE 0 END) as snr_excellent,
                SUM(CASE WHEN snr > 5 AND snr <= 10 THEN 1 ELSE 0 END) as snr_good,
                SUM(CASE WHEN snr > 0 AND snr <= 5 THEN 1 ELSE 0 END) as snr_fair,
                SUM(CASE WHEN snr IS NOT NULL AND snr <= 0 THEN 1 ELSE 0 END) as snr_poor
            FROM packet_history
            WHERE {where_clause}
            """,
            params,
        )
        row = cursor.fetchone()

        total = row["total_packets"] or 0
        successful = row["successful_packets"] or 0

        packet_statistics = {
            "total_packets": total,
            "successful_packets": successful,
            "failed_packets": total - successful,
            "success_rate": round(successful / total * 100, 2) if total > 0 else 0,
            "average_payload_size": round(row["avg_payload_size"] or 0, 2),
        }

        rssi_count = row["rssi_count"] or 0
        snr_count = row["snr_count"] or 0
        if rssi_count == 0 and snr_count == 0:
            signal_quality: dict[str, Any] = {
                "avg_rssi": None,
                "avg_snr": None,
                "rssi_distribution": {},
                "snr_distribution": {},
                "total_measurements": 0,
            }
        else:
            signal_quality = {
                "avg_rssi": round(row["avg_rssi"], 2) if row["avg_rssi"] else None,
                "avg_snr": round(row["avg_snr"], 2) if row["avg_snr"] else None,
                "rssi_distribution": {
                    "excellent": row["rssi_excellent"] or 0,
                    "good": row["rssi_good"] or 0,
                    "fair": row["rssi_fair"] or 0,
                    "poor": row["rssi_poor"] or 0,
                },
                "snr_distribution": {
                    "excellent": row["snr_excellent"] or 0,
                    "good": row["snr_good"] or 0,
                    "fair": row["snr_fair"] or 0,
                    "poor": row["snr_poor"] or 0,
                },
                "total_measurements": max(rssi_count, snr_count),
            }

        return {"packet_statistics": packet_statistics, "signal_quality": signal_quality}

    @staticmethod
    def _get_node_activity_statistics(
        cursor: Any, filters: dict, since_timestamp: float
    ) -> dict[str, Any]:
        cursor.execute("SELECT COUNT(*) as total_nodes FROM node_info")
        total_nodes = cursor.fetchone()["total_nodes"]

        where_clause, params = AnalyticsService._build_where(
            filters, since_timestamp, include_from_node=False
        )

        cursor.execute(
            f"""
            WITH node_activity AS (
                SELECT from_node_id, COUNT(*) as packet_count
                FROM packet_history
                WHERE from_node_id IS NOT NULL AND {where_clause}
                GROUP BY from_node_id
            )
            SELECT
                COUNT(*) as active_nodes,
                SUM(CASE WHEN packet_count > 100 THEN 1 ELSE 0 END) as very_active,
                SUM(CASE WHEN packet_count > 10 AND packet_count <= 100 THEN 1 ELSE 0 END) as moderately_active,
                SUM(CASE WHEN packet_count >= 1 AND packet_count <= 10 THEN 1 ELSE 0 END) as lightly_active
            FROM node_activity
            """,
            params,
        )
        row = cursor.fetchone()

        active_nodes = row["active_nodes"] or 0
        return {
            "total_nodes": total_nodes,
            "active_nodes": active_nodes,
            "inactive_nodes": total_nodes - active_nodes,
            "activity_rate": round(active_nodes / total_nodes * 100, 2) if total_nodes > 0 else 0,
            "activity_distribution": {
                "very_active": row["very_active"] or 0,
                "moderately_active": row["moderately_active"] or 0,
                "lightly_active": row["lightly_active"] or 0,
                "inactive": total_nodes - active_nodes,
            },
        }

    @staticmethod
    def _get_temporal_patterns(
        cursor: Any, filters: dict, since_timestamp: float
    ) -> dict[str, Any]:
        where_clause, params = AnalyticsService._build_where(
            filters, since_timestamp, include_hop_count=True
        )

        cursor.execute(
            f"""
            SELECT
                CAST(strftime('%H', datetime(timestamp, 'unixepoch')) AS INTEGER) AS hour,
                COUNT(*) AS total_packets,
                SUM(CASE WHEN processed_successfully = 1 THEN 1 ELSE 0 END) AS successful_packets
            FROM packet_history
            WHERE {where_clause}
            GROUP BY hour
            """,
            params,
        )
        rows = cursor.fetchall()

        hourly_counts: dict[int, int] = defaultdict(int)
        hourly_success: dict[int, int] = defaultdict(int)
        for row in rows:
            h = row["hour"]
            hourly_counts[h] = row["total_packets"]
            hourly_success[h] = row["successful_packets"]

        hourly_data = []
        for h in range(24):
            count = hourly_counts.get(h, 0)
            success = hourly_success.get(h, 0)
            hourly_data.append({
                "hour": h,
                "total_packets": count,
                "successful_packets": success,
                "success_rate": round(success / count * 100, 2) if count > 0 else 0,
            })

        return {
            "hourly_breakdown": hourly_data,
            "peak_hour": max(hourly_counts, key=lambda x: hourly_counts[x]) if hourly_counts else None,
            "quiet_hour": min(hourly_counts, key=lambda x: hourly_counts[x]) if hourly_counts else None,
        }

    @staticmethod
    def _get_top_active_nodes(cursor: Any, since_timestamp: float) -> list[dict[str, Any]]:
        """Direct query — avoids the full get_nodes() machinery (pagination, count, JOINs)."""
        cursor.execute(
            """
            SELECT
                ph.from_node_id,
                ni.long_name,
                ni.short_name,
                ni.hw_model,
                COUNT(*) as packet_count,
                AVG(CASE WHEN ph.rssi IS NOT NULL AND ph.rssi != 0 THEN ph.rssi END) as avg_rssi,
                AVG(ph.snr) as avg_snr,
                MAX(ph.timestamp) as last_seen
            FROM packet_history ph
            LEFT JOIN node_info ni ON ph.from_node_id = ni.node_id
            WHERE ph.timestamp >= ? AND ph.from_node_id IS NOT NULL
            GROUP BY ph.from_node_id
            ORDER BY packet_count DESC
            LIMIT 10
            """,
            [since_timestamp],
        )
        rows = cursor.fetchall()

        return [
            {
                "node_id": row["from_node_id"],
                "display_name": (
                    row["long_name"] or row["short_name"]
                    or f"!{row['from_node_id']:08x}"
                ),
                "packet_count": row["packet_count"],
                "avg_rssi": round(row["avg_rssi"], 1) if row["avg_rssi"] else None,
                "avg_snr": round(row["avg_snr"], 1) if row["avg_snr"] else None,
                "last_seen": row["last_seen"],
                "hw_model": row["hw_model"],
            }
            for row in rows
        ]

    @staticmethod
    def _get_packet_type_distribution(
        cursor: Any, filters: dict, since_timestamp: float
    ) -> list[dict[str, Any]]:
        where_clause, params = AnalyticsService._build_where(
            filters, since_timestamp
        )

        cursor.execute(
            f"""
            WITH type_counts AS (
                SELECT portnum_name, COUNT(*) as count
                FROM packet_history
                WHERE portnum_name IS NOT NULL AND {where_clause}
                GROUP BY portnum_name
            ),
            total_count AS (SELECT SUM(count) as total FROM type_counts)
            SELECT tc.portnum_name, tc.count,
                   ROUND(tc.count * 100.0 / t.total, 2) as percentage
            FROM type_counts tc, total_count t
            ORDER BY tc.count DESC
            LIMIT 15
            """,
            params,
        )
        return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def _get_gateway_distribution(
        cursor: Any, filters: dict, since_timestamp: float
    ) -> list[dict[str, Any]]:
        where_clause, params = AnalyticsService._build_where(
            filters, since_timestamp, include_gateway=False
        )

        cursor.execute(
            f"""
            WITH gateway_stats AS (
                SELECT
                    COALESCE(gateway_id, 'Unknown') as gateway_id,
                    COUNT(*) as total_packets,
                    SUM(CASE WHEN processed_successfully = 1 THEN 1 ELSE 0 END) as successful_packets
                FROM packet_history
                WHERE {where_clause}
                GROUP BY gateway_id
            ),
            total_count AS (SELECT SUM(total_packets) as total FROM gateway_stats)
            SELECT
                gs.gateway_id,
                gs.total_packets,
                gs.successful_packets,
                ROUND(gs.successful_packets * 100.0 / gs.total_packets, 2) as success_rate,
                ROUND(gs.total_packets * 100.0 / t.total, 2) as percentage_of_total
            FROM gateway_stats gs, total_count t
            ORDER BY gs.total_packets DESC
            LIMIT 20
            """,
            params,
        )
        return [dict(row) for row in cursor.fetchall()]
