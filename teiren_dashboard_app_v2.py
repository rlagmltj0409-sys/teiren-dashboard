from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


# =========================================================
# PAGE
# =========================================================
st.set_page_config(
    page_title="TEIREN Security Dashboard",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)

BASE_DIR = Path(__file__).resolve().parent
USER_PATH = BASE_DIR / "final_user_risk_score_8feature.csv"
DAILY_PATH = BASE_DIR / "final_daily_risk_score_8feature.csv"


# =========================================================
# STYLE — dark SIEM / SOC dashboard
# =========================================================
st.markdown(
    """
    <style>
    :root {
        --bg: #07111e;
        --panel: #0c1a2a;
        --panel2: #102235;
        --line: rgba(119, 176, 197, .16);
        --text: #eef6fb;
        --muted: #8da2b5;
        --cyan: #36c7d7;
        --cyan2: #6ee7ef;
        --purple: #7e78f2;
        --danger: #ff5c70;
    }

    html, body, [class*="css"] {
        font-family: Inter, Pretendard, "Noto Sans KR", sans-serif;
    }

    .stApp {
        background:
            radial-gradient(circle at 90% 5%, rgba(54,199,215,.08), transparent 25%),
            linear-gradient(180deg, #06101c 0%, #081421 100%);
        color: var(--text);
    }

    .block-container {
        max-width: 1480px;
        padding: 1.7rem 2rem 3rem 2rem;
    }

    #MainMenu, footer, header {visibility: hidden;}

    .brand {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 2px;
    }

    .brand-mark {
        width: 34px;
        height: 34px;
        border-radius: 10px;
        background: linear-gradient(135deg, #2ed0df 0%, #6f74ef 100%);
        box-shadow: 0 0 24px rgba(54,199,215,.20);
    }

    .brand-title {
        font-size: 1.72rem;
        line-height: 1;
        font-weight: 800;
        letter-spacing: -0.03em;
        color: #f7fbfd;
    }

    .brand-sub {
        color: var(--muted);
        font-size: .88rem;
        margin: .55rem 0 1.25rem 0;
    }

    .section-title {
        margin-top: 1.3rem;
        margin-bottom: .15rem;
        font-size: 1.12rem;
        font-weight: 760;
        color: #edf6fa;
        letter-spacing: -0.02em;
    }

    .section-sub {
        color: #7f94a8;
        font-size: .82rem;
        margin-bottom: .75rem;
    }

    .kpi {
        min-height: 116px;
        padding: 1.05rem 1.1rem;
        border-radius: 15px;
        background:
            linear-gradient(145deg, rgba(16,34,53,.98), rgba(10,24,39,.98));
        border: 1px solid var(--line);
        box-shadow:
            inset 0 1px 0 rgba(255,255,255,.025),
            0 12px 24px rgba(0,0,0,.18);
    }

    .kpi-label {
        color: #8096aa;
        font-size: .75rem;
        font-weight: 650;
        letter-spacing: .02em;
        text-transform: uppercase;
    }

    .kpi-value {
        margin-top: .48rem;
        color: #f8fcff;
        font-size: 1.75rem;
        font-weight: 820;
        letter-spacing: -0.03em;
        line-height: 1.05;
    }

    .kpi-foot {
        margin-top: .55rem;
        color: #40c9d8;
        font-size: .76rem;
    }

    .hero-card {
        padding: 1.1rem 1.25rem;
        border-radius: 16px;
        background:
            linear-gradient(135deg, rgba(18,43,61,.98), rgba(12,27,43,.98));
        border: 1px solid rgba(67, 203, 218, .23);
        box-shadow: 0 15px 35px rgba(0,0,0,.20);
    }

    .hero-user {
        color: #6ee7ef;
        font-size: 1.6rem;
        font-weight: 800;
        margin-top: .15rem;
    }

    .hero-score {
        color: #ffffff;
        font-size: 2.75rem;
        font-weight: 850;
        letter-spacing: -0.04em;
        line-height: 1;
        margin-top: .55rem;
    }

    .hero-meta {
        color: #8fa4b8;
        font-size: .82rem;
        margin-top: .65rem;
    }

    div[data-testid="stTabs"] button {
        color: #8ea3b7;
        font-weight: 650;
        padding-left: .4rem;
        padding-right: 1.2rem;
    }

    div[data-testid="stTabs"] button[aria-selected="true"] {
        color: #edf9fb;
    }

    div[data-testid="stTabs"] [data-baseweb="tab-highlight"] {
        background-color: #38c7d6;
    }

    div[data-baseweb="select"] > div {
        background-color: #0d1d2e !important;
        border-color: rgba(80,180,200,.20) !important;
        border-radius: 10px !important;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(90,180,200,.14);
        border-radius: 12px;
        overflow: hidden;
    }

    div[data-testid="stExpander"] {
        border: 1px solid rgba(90,180,200,.14);
        border-radius: 12px;
        background: rgba(12,26,42,.75);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# LOAD
# =========================================================
@st.cache_data
def load_data():
    user_df = pd.read_csv(USER_PATH)
    daily_df = pd.read_csv(DAILY_PATH)

    user_df["max_risk_day"] = pd.to_datetime(user_df["max_risk_day"], errors="coerce")
    daily_df["day"] = pd.to_datetime(daily_df["day"], errors="coerce")

    return user_df, daily_df


if not USER_PATH.exists() or not DAILY_PATH.exists():
    st.error(
        "app.py와 같은 폴더에 아래 두 CSV가 필요합니다.\n\n"
        "- final_user_risk_score_8feature.csv\n"
        "- final_daily_risk_score_8feature.csv"
    )
    st.stop()

user_df, daily_df = load_data()
user_df = user_df.dropna(subset=["max_risk_score", "risk_rank"]).copy()
valid_daily = daily_df.dropna(subset=["day", "daily_risk_score"]).copy()

DOMAIN_COLS = {
    "Logon / PC": "risk_logon_pc",
    "Device": "risk_device",
    "File": "risk_file",
    "HTTP": "risk_http",
    "Email": "risk_email",
}

FEATURE_COLS = {
    "After-hours Logon": "after_hours_logon_count_anomaly_score",
    "New PC": "new_pc_anomaly_score",
    "Device Connect": "device_connect_count_anomaly_score",
    "File Activity": "file_event_count_anomaly_score",
    "Suspicious HTTP Keyword": "suspicious_http_keyword_count_anomaly_score",
    "Email Count": "email_count_anomaly_score",
    "Email Total Size": "email_total_size_anomaly_score",
    "Attachment Count": "attachment_count_anomaly_score",
}

TEXT = "#91a6b9"
GRID = "rgba(137,165,184,.10)"
CYAN = "#41cbd8"
PURPLE = "#7d79f4"
DANGER = "#ff6073"


def clean_plot(fig, height=340):
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT),
        hoverlabel=dict(bgcolor="#102338", font_color="#ffffff"),
        showlegend=False,
    )
    fig.update_xaxes(
        gridcolor=GRID,
        zeroline=False,
        linecolor="rgba(255,255,255,.05)",
        tickfont=dict(color=TEXT),
        title_font=dict(color=TEXT),
    )
    fig.update_yaxes(
        gridcolor=GRID,
        zeroline=False,
        linecolor="rgba(255,255,255,.05)",
        tickfont=dict(color=TEXT),
        title_font=dict(color=TEXT),
    )
    return fig


def kpi(label, value, foot):
    st.markdown(
        f"""
        <div class="kpi">
            <div class="kpi-label">{label}</div>
            <div class="kpi-value">{value}</div>
            <div class="kpi-foot">{foot}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# =========================================================
# HEADER
# =========================================================
st.markdown(
    """
    <div class="brand">
        <div class="brand-mark"></div>
        <div class="brand-title">TEIREN Security Dashboard</div>
    </div>
    <div class="brand-sub">
        사용자 행동 기준선 기반 이상탐지 · 위험 스코어링 결과
    </div>
    """,
    unsafe_allow_html=True,
)

tab_all, tab_daily = st.tabs(["전체 기간 위험 현황", "일일 위험 현황"])


# =========================================================
# TAB 1 — 전체 기간 MAX RISK
# =========================================================
with tab_all:
    period_start = valid_daily["day"].min()
    period_end = valid_daily["day"].max()

    rank_df = user_df.sort_values("risk_rank").reset_index(drop=True)
    top_row = rank_df.iloc[0]

    st.markdown('<div class="section-title">전체 기간 요약</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-sub">각 사용자의 전체 분석기간 중 최대 위험점수(max_risk_score)를 기준으로 순위를 산정합니다.</div>',
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi("분석 사용자", f"{user_df['user'].nunique():,}명", "max risk score 산출 사용자")
    with c2:
        kpi(
            "분석 기간",
            f"{(period_end - period_start).days + 1:,}일",
            f"{period_start:%Y-%m-%d} ~ {period_end:%Y-%m-%d}",
        )
    with c3:
        kpi("전체 1위 사용자", str(top_row["user"]), f"위험 발생일 {top_row['max_risk_day']:%Y-%m-%d}")
    with c4:
        kpi("최고 위험 점수", f"{top_row['max_risk_score']:.2f}", "전체 사용자 MAX 기준")

    left, right = st.columns([1.42, 1])

    with left:
        st.markdown('<div class="section-title">전체 기간 위험 사용자 Top 10</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="section-sub">사용자별 1년여 기간 중 가장 높았던 위험점수를 비교합니다.</div>',
            unsafe_allow_html=True,
        )

        top10 = rank_df.head(10).copy().sort_values("max_risk_score")
        fig = go.Figure(
            go.Bar(
                x=top10["max_risk_score"],
                y=top10["user"],
                orientation="h",
                text=top10["max_risk_score"].map(lambda x: f"{x:.2f}"),
                textposition="outside",
                marker=dict(
                    color=top10["max_risk_score"],
                    colorscale=[
                        [0.0, "#29435a"],
                        [0.6, "#2c99af"],
                        [1.0, "#67dce5"],
                    ],
                ),
                hovertemplate="<b>%{y}</b><br>Max Risk Score: %{x:.2f}<extra></extra>",
            )
        )
        fig.update_xaxes(title="Max Risk Score")
        fig.update_yaxes(title="")
        clean_plot(fig, 390)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with right:
        st.markdown('<div class="section-title">Rank #1 위험 구성</div>', unsafe_allow_html=True)
        st.markdown(
            f'<div class="section-sub">{top_row["user"]} · {top_row["max_risk_day"]:%Y-%m-%d}</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            f"""
            <div class="hero-card">
                <div class="kpi-label">HIGHEST-RISK USER</div>
                <div class="hero-user">{top_row["user"]}</div>
                <div class="hero-score">{top_row["max_risk_score"]:.2f}</div>
                <div class="hero-meta">Risk Rank #1 · Peak Day {top_row["max_risk_day"]:%Y-%m-%d}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        domain_df = pd.DataFrame(
            {
                "domain": list(DOMAIN_COLS.keys()),
                "score": [
                    float(top_row[col]) if pd.notna(top_row[col]) else 0.0
                    for col in DOMAIN_COLS.values()
                ],
            }
        ).sort_values("score")

        fig_d = go.Figure(
            go.Bar(
                x=domain_df["score"],
                y=domain_df["domain"],
                orientation="h",
                text=domain_df["score"].map(lambda x: f"{x:.2f}"),
                textposition="outside",
                marker_color=CYAN,
                hovertemplate="<b>%{y}</b><br>Contribution: %{x:.2f}<extra></extra>",
            )
        )
        fig_d.update_xaxes(title="Risk Contribution")
        fig_d.update_yaxes(title="")
        clean_plot(fig_d, 265)
        st.plotly_chart(fig_d, use_container_width=True, config={"displayModeBar": False})

    st.markdown('<div class="section-title">사용자 상세 조회</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-sub">상위 사용자 중 한 명을 선택하면 해당 사용자의 전체 기간 위험 추이와 최대 위험일의 세부 신호를 확인할 수 있습니다.</div>',
        unsafe_allow_html=True,
    )

    detail_users = rank_df.head(50)["user"].tolist()
    selected_user = st.selectbox(
        "사용자 선택",
        detail_users,
        index=0,
        key="alltime_user_select",
    )

    selected_user_row = rank_df.loc[rank_df["user"] == selected_user].iloc[0]
    selected_daily = (
        valid_daily.loc[valid_daily["user"] == selected_user]
        .sort_values("day")
        .copy()
    )

    a, b = st.columns([1.55, 1])

    with a:
        fig_t = go.Figure()
        fig_t.add_trace(
            go.Scatter(
                x=selected_daily["day"],
                y=selected_daily["daily_risk_score"],
                mode="lines",
                line=dict(color=CYAN, width=2),
                fill="tozeroy",
                fillcolor="rgba(65,203,216,.05)",
                hovertemplate="%{x|%Y-%m-%d}<br>Risk Score: %{y:.2f}<extra></extra>",
            )
        )
        fig_t.add_trace(
            go.Scatter(
                x=[selected_user_row["max_risk_day"]],
                y=[selected_user_row["max_risk_score"]],
                mode="markers",
                marker=dict(size=11, color=DANGER, line=dict(color="#ffd2d8", width=2)),
                hovertemplate="Peak Day<br>%{x|%Y-%m-%d}<br>%{y:.2f}<extra></extra>",
            )
        )
        fig_t.update_xaxes(title="")
        fig_t.update_yaxes(title="Daily Risk Score")
        clean_plot(fig_t, 330)
        st.plotly_chart(fig_t, use_container_width=True, config={"displayModeBar": False})

    with b:
        st.markdown(
            f"""
            <div class="hero-card">
                <div class="kpi-label">SELECTED USER</div>
                <div class="hero-user">{selected_user}</div>
                <div class="hero-score">{selected_user_row["max_risk_score"]:.2f}</div>
                <div class="hero-meta">
                    Rank #{int(selected_user_row["risk_rank"])}
                    · Peak Day {selected_user_row["max_risk_day"]:%Y-%m-%d}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        feature_df = pd.DataFrame(
            {
                "Feature": list(FEATURE_COLS.keys()),
                "Anomaly Score": [
                    float(selected_user_row[col]) if pd.notna(selected_user_row[col]) else 0.0
                    for col in FEATURE_COLS.values()
                ],
            }
        ).sort_values("Anomaly Score", ascending=False)

        st.dataframe(
            feature_df.head(5),
            use_container_width=True,
            hide_index=True,
            column_config={
                "Anomaly Score": st.column_config.NumberColumn(format="%.3f")
            },
            height=230,
        )

    st.markdown('<div class="section-title">전체 위험 순위</div>', unsafe_allow_html=True)
    ranking_table = rank_df[
        ["risk_rank", "user", "max_risk_day", "max_risk_score"]
    ].copy()
    ranking_table["max_risk_day"] = ranking_table["max_risk_day"].dt.strftime("%Y-%m-%d")
    ranking_table["max_risk_score"] = ranking_table["max_risk_score"].round(2)
    ranking_table.columns = ["Rank", "User", "Max Risk Day", "Max Risk Score"]

    st.dataframe(
        ranking_table.head(30),
        use_container_width=True,
        hide_index=True,
        height=560,
        column_config={
            "Rank": st.column_config.NumberColumn(width="small"),
            "Max Risk Score": st.column_config.NumberColumn(format="%.2f"),
        },
    )


# =========================================================
# TAB 2 — DAILY
# =========================================================
with tab_daily:
    dates = sorted(valid_daily["day"].dt.date.unique())
    default_date = top_row["max_risk_day"].date()
    default_idx = dates.index(default_date) if default_date in dates else len(dates) - 1

    date_col, _ = st.columns([1, 3])
    with date_col:
        selected_date = st.selectbox(
            "조회 날짜",
            dates,
            index=default_idx,
            format_func=lambda x: x.strftime("%Y-%m-%d"),
            key="daily_date_select",
        )

    selected_ts = pd.Timestamp(selected_date)
    day_df = (
        valid_daily.loc[valid_daily["day"] == selected_ts]
        .sort_values("daily_risk_score", ascending=False)
        .reset_index(drop=True)
    )

    if day_df.empty:
        st.info("선택한 날짜의 유효 위험 점수가 없습니다.")
    else:
        day_top = day_df.iloc[0]

        st.markdown('<div class="section-title">선택일 요약</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="section-sub">선택한 날짜의 daily_risk_score를 기준으로 위험 사용자를 확인합니다.</div>',
            unsafe_allow_html=True,
        )

        d1, d2, d3 = st.columns(3)
        with d1:
            kpi("조회 날짜", selected_date.strftime("%Y-%m-%d"), "Daily risk score 기준")
        with d2:
            kpi("최고 위험 사용자", str(day_top["user"]), "해당 날짜 1위")
        with d3:
            kpi("최고 일일 위험 점수", f"{day_top['daily_risk_score']:.2f}", "선택 날짜 MAX")

        x1, x2 = st.columns([1.45, 1])

        with x1:
            st.markdown('<div class="section-title">선택일 Top 10</div>', unsafe_allow_html=True)
            top_day_10 = day_df.head(10).copy().sort_values("daily_risk_score")

            fig_day = go.Figure(
                go.Bar(
                    x=top_day_10["daily_risk_score"],
                    y=top_day_10["user"],
                    orientation="h",
                    text=top_day_10["daily_risk_score"].map(lambda x: f"{x:.2f}"),
                    textposition="outside",
                    marker=dict(
                        color=top_day_10["daily_risk_score"],
                        colorscale=[
                            [0.0, "#29435a"],
                            [0.6, "#2c99af"],
                            [1.0, "#67dce5"],
                        ],
                    ),
                    hovertemplate="<b>%{y}</b><br>Daily Risk Score: %{x:.2f}<extra></extra>",
                )
            )
            fig_day.update_xaxes(title="Daily Risk Score")
            fig_day.update_yaxes(title="")
            clean_plot(fig_day, 390)
            st.plotly_chart(fig_day, use_container_width=True, config={"displayModeBar": False})

        with x2:
            st.markdown(
                f'<div class="section-title">{day_top["user"]} · 영역별 기여</div>',
                unsafe_allow_html=True,
            )

            day_domain = pd.DataFrame(
                {
                    "domain": list(DOMAIN_COLS.keys()),
                    "score": [
                        float(day_top[col]) if pd.notna(day_top[col]) else 0.0
                        for col in DOMAIN_COLS.values()
                    ],
                }
            ).sort_values("score")

            fig_dd = go.Figure(
                go.Bar(
                    x=day_domain["score"],
                    y=day_domain["domain"],
                    orientation="h",
                    text=day_domain["score"].map(lambda x: f"{x:.2f}"),
                    textposition="outside",
                    marker_color=PURPLE,
                    hovertemplate="<b>%{y}</b><br>Contribution: %{x:.2f}<extra></extra>",
                )
            )
            fig_dd.update_xaxes(title="Risk Contribution")
            fig_dd.update_yaxes(title="")
            clean_plot(fig_dd, 390)
            st.plotly_chart(fig_dd, use_container_width=True, config={"displayModeBar": False})

        daily_table = day_df[
            ["user", "daily_risk_score", "risk_logon_pc", "risk_device", "risk_file", "risk_http", "risk_email"]
        ].head(30).copy()

        daily_table["daily_risk_score"] = daily_table["daily_risk_score"].round(2)
        daily_table.columns = [
            "User", "Daily Risk Score", "Logon/PC", "Device", "File", "HTTP", "Email"
        ]

        st.markdown('<div class="section-title">선택일 위험 순위</div>', unsafe_allow_html=True)
        st.dataframe(
            daily_table,
            use_container_width=True,
            hide_index=True,
            height=520,
            column_config={
                "Daily Risk Score": st.column_config.NumberColumn(format="%.2f"),
                "Logon/PC": st.column_config.NumberColumn(format="%.2f"),
                "Device": st.column_config.NumberColumn(format="%.2f"),
                "File": st.column_config.NumberColumn(format="%.2f"),
                "HTTP": st.column_config.NumberColumn(format="%.2f"),
                "Email": st.column_config.NumberColumn(format="%.2f"),
            },
        )


st.caption(
    "※ 전체 기간 화면은 사용자별 max_risk_score, 일일 화면은 daily_risk_score를 사용합니다. "
    "별도의 위험 임계값이나 label 판정은 화면에 추가하지 않았습니다."
)
