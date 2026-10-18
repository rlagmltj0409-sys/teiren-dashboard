"""SBOM Insight · Grype vulnerability analysis MVP.

Run: streamlit run app2.py  (image-scoped exploration build of app.py)
Reads either streamlit_data_bundle.zip or data/processed/CSV files.
All metrics are computed from the supplied scan snapshot, not live data.
"""
from __future__ import annotations

import html
import io
import json
import zipfile
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent
SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
SEVERITY_COLORS = {
    "Critical": "#8E3B46", "High": "#B04A4A", "Medium": "#C59A3D",
    "Low": "#6F8BA6", "Negligible": "#7F9C8F", "Unknown": "#A7B0BA",
}
SEVERITY_BG = {
    "Critical": "#F3E5E7", "High": "#F7EBEB", "Medium": "#F8F1E3",
    "Low": "#ECF0F5", "Negligible": "#EDF3F0", "Unknown": "#F1F3F5",
}
NAVY = "#1F3A5F"
SLATE = "#355C7D"
MUTED = "#7C8B9C"
GRID = "#EDF0F4"
ALL_IMAGES = "__all__"
NUM_FORMAT = {"CVSS": "{:.1f}", "EPSS (%)": "{:.3f}", "Risk": "{:.4f}"}
PAGES = [":material/dashboard: 전체 현황", ":material/account_tree: 이미지 구조",
         ":material/manage_search: 취약점 상세", ":material/fact_check: 분석 기준"]


def read_csv_bytes(raw: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(raw), encoding="utf-8-sig")


def read_zip_bytes(raw: bytes) -> tuple[pd.DataFrame, dict]:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        paths = {Path(name).name: name for name in archive.namelist() if not name.endswith("/")}
        if "matches.csv" not in paths:
            raise ValueError("ZIP 파일 안에 matches.csv가 없습니다.")
        df = read_csv_bytes(archive.read(paths["matches.csv"]))
        meta = json.loads(archive.read(paths["scan_info.json"]).decode("utf-8-sig")) if "scan_info.json" in paths else {}
    return prepare_matches(df), meta


def prepare_matches(df: pd.DataFrame) -> pd.DataFrame:
    required = {"package", "version", "cve", "severity"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"필요한 CSV 컬럼이 없습니다: {', '.join(sorted(missing))}")
    df = df.copy()
    for col in ("cvss_score", "epss", "risk"):
        if col not in df:
            df[col] = float("nan")
        df[col] = pd.to_numeric(df[col], errors="coerce")
    for col in ("description", "fix_state", "image", "image_digest", "distro", "grype_version", "db_built", "scanned_at", "cvss_vector", "namespace", "match_type", "fix_versions"):
        if col not in df:
            df[col] = ""
    for col in ("package", "version", "cve", "severity"):
        df[col] = df[col].fillna("Unknown").astype(str)
    df["severity"] = df["severity"].where(df["severity"].isin(SEVERITIES), "Unknown")
    df["image"] = df["image"].fillna("").astype(str).str.strip().replace("", "이미지 정보 없음")
    df["image_digest"] = df["image_digest"].fillna("").astype(str).str.strip()
    df["image_key"] = df["image"] + "@" + df["image_digest"]
    df["image_label"] = df["image"] + df["image_digest"].map(short_digest).map(lambda d: f" · {d}" if d else "")
    return df


def short_digest(digest: str) -> str:
    return str(digest).removeprefix("sha256:")[:12]


def image_options(df: pd.DataFrame) -> pd.DataFrame:
    return (df.groupby(["image_key", "image", "image_digest", "image_label"], as_index=False)
              .agg(match_count=("cve", "size"), unique_cve_count=("cve", "nunique"),
                   package_count=("package", "nunique"),
                   high_count=("severity", lambda s: int(s.isin(["High", "Critical"]).sum())),
                   distro=("distro", lambda s: ", ".join(sorted({str(v) for v in s.dropna() if str(v)})) or "정보 없음"))
              .sort_values(["match_count", "image_label"], ascending=[False, True]))


def scope_meta(meta: dict, df: pd.DataFrame) -> dict:
    """Keep scan_info.json values only when they describe the selected image scope."""
    scoped = dict(meta)
    images = df["image_key"].unique()
    if len(images) > 1:
        scoped.update(image=f"이미지 {len(images)}개", image_digest="여러 이미지")
        for key in ("distro", "scanned_at", "grype_version", "db_built"):
            values = sorted({str(v) for v in df[key].dropna() if str(v)})
            scoped[key] = " / ".join(values) if values else "정보 없음"
    elif (meta.get("image") and meta["image"] != df["image"].iloc[0]) or (meta.get("image_digest") and meta["image_digest"] != df["image_digest"].iloc[0]):
        for key in ("image", "image_digest", "distro", "scanned_at"):
            scoped.pop(key, None)
    return scoped


def load_local() -> tuple[pd.DataFrame, dict, str]:
    zip_candidates = [
        BASE_DIR / "data" / "processed" / "streamlit_data_bundle.zip",
        BASE_DIR / "streamlit_data_bundle.zip",
    ]
    for path in zip_candidates:
        if path.is_file():
            df, meta = read_zip_bytes(path.read_bytes())
            return df, meta, str(path.relative_to(BASE_DIR))
    for folder in (BASE_DIR / "data" / "processed", BASE_DIR):
        csv_path = folder / "matches.csv"
        if csv_path.is_file():
            df = prepare_matches(pd.read_csv(csv_path, encoding="utf-8-sig"))
            info_path = folder / "scan_info.json"
            meta = json.loads(info_path.read_text(encoding="utf-8-sig")) if info_path.exists() else {}
            return df, meta, str(csv_path.relative_to(BASE_DIR))
    raise FileNotFoundError("streamlit_data_bundle.zip 또는 data/processed/matches.csv를 찾지 못했습니다.")


def get_meta(meta: dict, df: pd.DataFrame, key: str, default: str = "정보 없음") -> str:
    value = meta.get(key)
    if value not in (None, ""):
        return str(value)
    if key in df.columns and not df.empty:
        available = df[key].dropna().astype(str)
        if not available.empty and available.iloc[0]:
            return available.iloc[0]
    return default


def date_part(value: str) -> str:
    if not value or value == "정보 없음":
        return "정보 없음"
    return value[:10]


def severity_count(df: pd.DataFrame, count_type: str = "matches") -> pd.Series:
    if count_type == "cve":
        tmp = df.drop_duplicates("cve").copy()
    else:
        tmp = df
    return tmp["severity"].value_counts().reindex(SEVERITIES, fill_value=0)


def cve_rollup(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["cve", "severity", "cvss_score", "epss", "risk", "packages", "package_count", "images", "image_count", "match_count"])
    agg = (df.groupby("cve", as_index=False)
             .agg(severity=("severity", "first"), cvss_score=("cvss_score", "max"),
                  epss=("epss", "max"), risk=("risk", "max"),
                  packages=("package", lambda x: ", ".join(sorted(x.unique()))),
                  package_count=("package", "nunique"),
                  images=("image_label", lambda x: ", ".join(sorted(x.unique()))),
                  image_count=("image_key", "nunique"), match_count=("cve", "size")))
    return agg.sort_values(["risk", "cvss_score", "cve"], ascending=[False, False, True], na_position="last")


def pkg_rollup(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["package", "version", "match_count", "unique_cve_count", "max_cvss", "max_risk", "images"])
    result = (df.groupby(["package", "version"], as_index=False)
              .agg(match_count=("cve", "size"), unique_cve_count=("cve", "nunique"),
                   max_cvss=("cvss_score", "max"), max_risk=("risk", "max"),
                   images=("image_label", lambda x: ", ".join(sorted(x.unique())))))
    return result.sort_values(["match_count", "max_risk", "package"], ascending=[False, False, True])


def fig_layout(fig: go.Figure, *, height: int = 320, margin_left: int = 10, margin_right: int = 10) -> go.Figure:
    fig.update_layout(
        height=height, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#4A5568", "size": 12},
        margin={"t": 16, "b": 18, "l": margin_left, "r": margin_right},
        showlegend=False, bargap=0.42,
        hoverlabel={"bgcolor": "white", "bordercolor": "#D5DBE3", "font": {"size": 12, "color": "#1F2A37"}},
    )
    fig.update_xaxes(gridcolor=GRID, zeroline=False, linecolor="#DFE4EA",
                     tickfont={"color": MUTED, "size": 11}, title_font={"color": MUTED, "size": 11})
    fig.update_yaxes(gridcolor=GRID, zeroline=False, tickfont={"color": "#4A5568"})
    return fig


def severity_table(table: pd.DataFrame, col: str = "심각도"):
    fmt = {k: v for k, v in NUM_FORMAT.items() if k in table.columns}
    return (table.style
            .map(lambda s: f"color:{SEVERITY_COLORS.get(s, MUTED)};background-color:{SEVERITY_BG.get(s, '#FFFFFF')}", subset=[col])
            .format(fmt, na_rep="—"))


def severity_fig(df: pd.DataFrame) -> go.Figure:
    values = severity_count(df)
    labels = [s for s in SEVERITIES if values[s] > 0]
    fig = go.Figure(go.Pie(
        labels=labels, values=[int(values[s]) for s in labels], hole=0.72,
        sort=False, textinfo="label+percent", textposition="outside", textfont={"color": "#4A5568", "size": 12},
        marker={"colors": [SEVERITY_COLORS[s] for s in labels], "line": {"color": "white", "width": 2}},
        hovertemplate="%{label}: %{value}건 (%{percent})<extra></extra>",
    ))
    fig_layout(fig, height=340, margin_left=48, margin_right=48)
    fig.update_layout(annotations=[dict(text=f"<b>{len(df)}건</b><br><span style='font-size:11px;color:{MUTED}'>전체 매칭</span>", x=.5, y=.5, showarrow=False, font={"size": 20, "color": NAVY})])
    return fig


def package_fig(df: pd.DataFrame) -> go.Figure:
    packages = pkg_rollup(df).head(8)
    dup = packages["package"].duplicated(keep=False)
    names = packages["package"].where(~dup, packages["package"] + " " + packages["version"])
    fig = go.Figure(go.Bar(
        x=packages["match_count"], y=names, orientation="h",
        marker_color=SLATE, text=packages["match_count"], textposition="outside", textfont={"color": "#4A5568"},
        customdata=packages[["version", "unique_cve_count", "images"]].to_numpy(),
        hovertemplate="%{y} %{customdata[0]}<br>탐지 매칭 %{x}건 · 고유 CVE %{customdata[1]}개<br>이미지: %{customdata[2]}<extra></extra>",
    ))
    fig_layout(fig, height=295, margin_left=10, margin_right=40)
    fig.update_layout(yaxis={"autorange": "reversed", "title": None}, xaxis={"title": "매칭 건수", "dtick": 2})
    return fig


def risk_fig(df: pd.DataFrame) -> go.Figure:
    top = cve_rollup(df).head(8)
    fig = go.Figure(go.Bar(
        x=top["risk"], y=top["cve"], orientation="h",
        marker_color=[SEVERITY_COLORS.get(s, MUTED) for s in top["severity"]],
        customdata=top[["severity", "packages", "images"]].to_numpy(),
        hovertemplate="<b>%{y}</b> · %{customdata[0]}<br>Risk 값 %{x:.4f}<br>이미지: %{customdata[2]}<br>패키지: %{customdata[1]}<extra></extra>",
    ))
    fig_layout(fig, height=340, margin_left=10, margin_right=18)
    fig.update_layout(yaxis={"autorange": "reversed", "title": None, "tickfont": {"size": 11}}, xaxis={"title": "Risk 값 (원본 데이터)"})
    return fig


def sankey_fig(df: pd.DataFrame) -> go.Figure:
    images = image_options(df)
    severities = [s for s in SEVERITIES if (df["severity"] == s).any()]
    package_names = df["package"].value_counts().index.tolist()
    nodes = [f"Docker 이미지<br>{label}" for label in images["image_label"]] + package_names + severities
    index = {k: i for i, k in enumerate(images["image_key"].tolist() + package_names + severities)}
    src: list[int] = []
    dst: list[int] = []
    weight: list[int] = []
    for (a, b), n in pd.concat([df.groupby(["image_key", "package"]).size(), df.groupby(["package", "severity"]).size()]).items():
        src.append(index[a]); dst.append(index[b]); weight.append(int(n))
    node_colors = [NAVY] * len(images) + ["#8796A8"] * len(package_names) + [SEVERITY_COLORS[x] for x in severities]
    fig = go.Figure(go.Sankey(
        arrangement="snap",
        node={"label": nodes, "color": node_colors, "pad": 20, "thickness": 14,
              "line": {"color": "#fff", "width": 0.5},
              "hovertemplate": "%{label}<extra></extra>"},
        link={"source": src, "target": dst, "value": weight,
              "color": "rgba(53,92,125,.13)",
              "hovertemplate": "연결된 탐지 매칭: %{value}건<extra></extra>"},
    ))
    fig_layout(fig, height=400, margin_left=15, margin_right=15)
    return fig


def chain_fig(rows: pd.DataFrame) -> go.Figure:
    """Image → package@version → CVE for one selected package (vulnerability links, not layers)."""
    images = rows.drop_duplicates("image_key")
    pkgs = rows.assign(pv=rows["package"] + " " + rows["version"]).drop_duplicates("pv")
    cves = cve_rollup(rows)
    keys = images["image_key"].tolist() + pkgs["pv"].tolist() + cves["cve"].tolist()
    index = {k: i for i, k in enumerate(keys)}
    labels = images["image_label"].tolist() + pkgs["pv"].tolist() + cves["cve"].tolist()
    fmt = lambda v, spec: format(v, spec) if pd.notna(v) else "—"
    info = (["Docker 이미지"] * len(images) + ["패키지 · 버전"] * len(pkgs)
            + [f"{r.severity} · CVSS {fmt(r.cvss_score, '.1f')} · Risk {fmt(r.risk, '.4f')}" for r in cves.itertuples()])
    colors = [NAVY] * len(images) + ["#8796A8"] * len(pkgs) + [SEVERITY_COLORS.get(s, MUTED) for s in cves["severity"]]
    pv = rows["package"] + " " + rows["version"]
    links = pd.concat([rows.assign(a=rows["image_key"], b=pv).groupby(["a", "b"]).size(),
                       rows.assign(a=pv, b=rows["cve"]).groupby(["a", "b"]).size()])
    fig = go.Figure(go.Sankey(
        arrangement="snap",
        node={"label": labels, "color": colors, "customdata": info, "pad": 10, "thickness": 12,
              "line": {"color": "#fff", "width": 0.5},
              "hovertemplate": "%{label}<br>%{customdata}<extra></extra>"},
        link={"source": [index[a] for a, _ in links.index], "target": [index[b] for _, b in links.index],
              "value": links.astype(int).tolist(), "color": "rgba(53,92,125,.13)",
              "hovertemplate": "%{source.label} → %{target.label}<extra></extra>"},
    ))
    fig_layout(fig, height=max(260, 30 * len(cves) + 60), margin_left=15, margin_right=15)
    return fig


def style() -> None:
    st.markdown("""
    <style>
    :root {--navy: #1F3A5F; --ink: #1F2A37; --muted: #6B7A8F; --faint: #8A97A8; --line: #E1E6EC;
           --shadow: 0 1px 2px rgba(16,24,40,.04), 0 2px 8px rgba(16,24,40,.04);
           --shadow-hover: 0 2px 4px rgba(16,24,40,.05), 0 8px 18px rgba(16,24,40,.06);}
    .block-container {padding-top: 2rem; padding-bottom: 4rem; max-width: 1400px;}
    header[data-testid='stHeader'] {background: transparent;}
    div[data-testid='stDecoration'] {display: none;}
    h1,h2,h3 {color: var(--navy); letter-spacing: -.01em;}

    section[data-testid='stSidebar'] [data-testid='stRadioGroup'] {align-items: stretch;}
    section[data-testid='stSidebar'] [data-testid='stRadioOption'] {width: 100%; max-width: none; box-sizing: border-box; padding: 8px 12px; margin: 1px 0; border-radius: 6px; transition: background .15s;}
    section[data-testid='stSidebar'] [data-testid='stRadioOption'] > div > div > div:not([data-testid]) {display: none;}
    section[data-testid='stSidebar'] [data-testid='stRadioOption']:hover {background: #F3F5F8;}
    section[data-testid='stSidebar'] [data-testid='stRadioOption'][data-selected='true'] {background: #EDF1F6; box-shadow: inset 3px 0 0 var(--navy);}
    section[data-testid='stSidebar'] [data-testid='stRadioOption'] p {font-size: 14px; color: #4A5568;}
    section[data-testid='stSidebar'] [data-testid='stRadioOption'][data-selected='true'] p {color: var(--navy); font-weight: 600;}
    .sb-brand {display: flex; align-items: center; gap: 10px; font-size: 17px; font-weight: 700; color: var(--navy); letter-spacing: -.01em; padding-top: 4px;}
    .sb-mark {width: 26px; height: 26px; border-radius: 6px; background: var(--navy); color: #fff; font-size: 13px; display: inline-flex; align-items: center; justify-content: center;}
    .sb-brand-sub {font-size: 10.5px; color: var(--faint); letter-spacing: .08em; margin-top: 6px;}
    .sb-rule {height: 1px; background: var(--line); margin: 16px 0;}
    .sb-stats {background: #F7F9FB; border: 1px solid var(--line); border-radius: 8px; padding: 4px 14px 12px; font-size: 12.5px; color: var(--ink);}
    .sb-k {font-size: 10.5px; font-weight: 600; color: var(--faint); letter-spacing: .06em; text-transform: uppercase; margin-top: 10px;}
    .sb-v {margin-top: 2px; word-break: break-all;}

    .page-eyebrow {font-size: 11px; font-weight: 600; color: var(--faint); letter-spacing: .1em; text-transform: uppercase;}
    .page-title {font-size: 24px; font-weight: 700; color: var(--ink); letter-spacing: -.015em; line-height: 1.3; margin-top: 4px;}
    .page-sub {font-size: 13px; color: var(--muted); margin: 4px 0 20px; padding-bottom: 16px; border-bottom: 1px solid var(--line);}

    .kpi {position: relative; background: #fff; border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px 14px 20px; min-height: 116px; box-shadow: var(--shadow); transition: box-shadow .2s, transform .2s;}
    .kpi::before {content: ''; position: absolute; left: 0; top: 16px; bottom: 16px; width: 3px; border-radius: 0 2px 2px 0; background: var(--accent, var(--navy));}
    .kpi:hover {box-shadow: var(--shadow-hover); transform: translateY(-1px);}
    .kpi-lbl {font-size: 12px; font-weight: 600; color: var(--muted); letter-spacing: .02em;}
    .kpi-val {font-size: 28px; font-weight: 700; color: var(--ink); line-height: 1.2; margin-top: 8px; letter-spacing: -.01em; font-variant-numeric: tabular-nums;}
    .kpi-unit {font-size: 14px; font-weight: 500; color: var(--muted); margin-left: 3px;}
    .kpi-note {font-size: 11.5px; color: var(--faint); margin-top: 6px;}

    div[class*='st-key-card'] {background: #fff; border-color: var(--line) !important; border-radius: 10px !important; box-shadow: var(--shadow); padding: 18px 20px !important;}
    .headline {font-size: 15px; font-weight: 600; color: var(--ink); margin-bottom: 2px;}
    .hint {font-size: 12px; color: var(--muted); margin-bottom: 4px;}
    .mini-tag {display: inline-flex; align-items: center; gap: 6px; background: #fff; border: 1px solid var(--line); color: #4A5568; border-radius: 999px; padding: 3px 10px; margin: 0 6px 10px 0; font-size: 12px;}
    .mini-tag i {width: 7px; height: 7px; border-radius: 50%; display: inline-block;}
    .mini-tag b {color: var(--ink); font-weight: 600;}

    div[data-testid='stMetric'] {background: #fff; border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; box-shadow: var(--shadow);}
    div[data-testid='stMetricLabel'] p {font-size: 12px; font-weight: 600; color: var(--muted);}
    div[data-testid='stDataFrame'] {border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: #fff;}
    div[data-testid='stExpander'] details {background: #fff; border-color: var(--line); border-radius: 10px; box-shadow: var(--shadow);}
    div[data-testid='stAlertContainer'] {border: 1px solid rgba(31,58,95,.08); border-radius: 8px;}
    [data-testid='stCaptionContainer'] {color: var(--faint);}

    .kv {display: grid; grid-template-columns: minmax(110px, 160px) 1fr; font-size: 13px; margin-top: 10px;}
    .kv-k, .kv-v {padding: 9px 0; border-top: 1px solid #EEF1F4;}
    .kv-k {color: var(--muted); font-weight: 600;}
    .kv-v {color: var(--ink); word-break: break-all;}
    .scope {display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin: -6px 0 18px; font-size: 12px; color: var(--muted);}
    .scope span {background: #fff; border: 1px solid var(--line); border-radius: 999px; padding: 3px 10px; color: #4A5568;}
    .scope b {color: var(--ink); font-weight: 600;}
    </style>
    """, unsafe_allow_html=True)


def page_header(title: str, subtitle: str) -> None:
    st.markdown(f"<div class='page-eyebrow'>SBOM Insight · Snapshot Report</div><div class='page-title'>{html.escape(title)}</div><div class='page-sub'>{html.escape(subtitle)}</div>", unsafe_allow_html=True)


def kpi_card(label: str, value: str, note: str, color: str = NAVY) -> None:
    num = value.rstrip("건개")
    st.markdown(
        f"<div class='kpi' style='--accent:{color}'>"
        f"<div class='kpi-lbl'>{html.escape(label)}</div>"
        f"<div class='kpi-val'>{html.escape(num)}<span class='kpi-unit'>{html.escape(value[len(num):])}</span></div>"
        f"<div class='kpi-note'>{html.escape(note)}</div></div>",
        unsafe_allow_html=True,
    )


def scope_bar(df: pd.DataFrame, df_all: pd.DataFrame) -> None:
    """Show which image the page is scoped to, separately from whole-dataset totals."""
    images = df["image_key"].unique()
    if len(images) == 1:
        row = df.iloc[0]
        target = f"<span>분석 범위 <b>{html.escape(row['image'])}</b></span>"
        if row["image_digest"]:
            target += f"<span>digest <b>{html.escape(short_digest(row['image_digest']))}…</b></span>"
    else:
        target = f"<span>분석 범위 <b>전체 이미지 {len(images)}개</b></span>"
    parts = [target, f"<span>매칭 <b>{len(df):,}건</b> · 고유 CVE <b>{df['cve'].nunique():,}개</b></span>"]
    if len(df) != len(df_all):
        parts.append(f"전체 데이터: 이미지 {df_all['image_key'].nunique()}개 · 매칭 {len(df_all):,}건 · 고유 CVE {df_all['cve'].nunique():,}개")
    st.markdown(f"<div class='scope'>{''.join(parts)}</div>", unsafe_allow_html=True)


def section_title(text: str, hint: str = "") -> None:
    st.markdown(f"<div class='headline'>{html.escape(text)}</div>" + (f"<div class='hint'>{html.escape(hint)}</div>" if hint else ""), unsafe_allow_html=True)


def overview(df: pd.DataFrame, meta: dict, df_all: pd.DataFrame) -> None:
    page_header("컨테이너 취약점 모니터링", "Docker 이미지 스캔 결과를 한눈에 확인하고, 먼저 검토할 항목을 찾는 대시보드 · 저장된 스냅샷")
    scope_bar(df, df_all)
    counts = severity_count(df)
    a,b,c,d = st.columns(4, gap="medium")
    with a: kpi_card("취약점 매칭", f"{len(df):,}건", "패키지 × CVE 조합", SLATE)
    with b: kpi_card("고유 CVE", f"{df['cve'].nunique():,}개", "중복 CVE를 한 번만 계산", MUTED)
    with c: kpi_card("High 이상 매칭", f"{int(counts['High'] + counts['Critical']):,}건", "High + Critical", SEVERITY_COLORS["High"])
    with d: kpi_card("매칭된 패키지", f"{df['package'].nunique():,}개", "전체 설치 패키지 수는 아님", NAVY)
    st.write("")
    left, right = st.columns([1, 1.2], gap="medium")
    with left:
        with st.container(border=True, key="card_1"):
            section_title("심각도별 탐지 현황", "Grype 매칭 건수 기준")
            st.plotly_chart(severity_fig(df), use_container_width=True, config={"displayModeBar": False})
    with right:
        with st.container(border=True, key="card_2"):
            section_title("우선 검토할 CVE TOP 8", "원본 Risk 지표 순 · 동일 CVE는 한 번만 표시")
            st.plotly_chart(risk_fig(df), use_container_width=True, config={"displayModeBar": False})
    with st.container(border=True, key="card_3"):
        section_title("패키지별 취약점 매칭", "어떤 패키지에서 취약점 후보가 많이 발견되었는가?")
        st.plotly_chart(package_fig(df), use_container_width=True, config={"displayModeBar": False})
    if df["image_key"].nunique() > 1:
        with st.container(border=True, key="card_images"):
            section_title("이미지별 요약", "이미지 이름과 digest 기준 · 같은 CVE가 여러 이미지에 있으면 이미지마다 따로 셉니다")
            summary = image_options(df)[["image", "image_digest", "distro", "match_count", "unique_cve_count", "package_count", "high_count"]]
            summary = summary.rename(columns={"image": "이미지", "image_digest": "Digest", "distro": "OS", "match_count": "매칭", "unique_cve_count": "고유 CVE", "package_count": "매칭된 패키지", "high_count": "High 이상 매칭"})
            st.dataframe(summary, use_container_width=True, hide_index=True)
    best = cve_rollup(df)
    if not best.empty:
        top = best.iloc[0]
        st.info(f"**검토 후보:** {top['cve']} · 이미지 {top['images']} · 관련 패키지 {top['packages']} · Risk {top['risk']:.4f}. 이 순위는 스캔 결과를 정렬한 것이며, 실제 영향·오탐·수정 가능 여부는 추가 검증이 필요해요.")
    st.caption(f"기준: {get_meta(meta, df, 'distro')} · Grype {get_meta(meta, df, 'grype_version')} · DB {date_part(get_meta(meta, df, 'db_built'))} (UTC). 실시간 모니터링이 아닌 단일 스캔 결과입니다.")


def structure(df: pd.DataFrame, meta: dict, df_all: pd.DataFrame) -> None:
    image = get_meta(meta, df, "image")
    page_header("이미지 구성과 취약점 연결", "Docker 이미지 → 탐지된 패키지 → 취약점 심각도의 연결 관계를 시각화합니다")
    scope_bar(df, df_all)
    st.warning("**해석 주의:** 아래 그림은 Docker 레이어 구조가 아닙니다. 취약점이 매칭된 패키지만 표시하며, 이미지의 전체 설치 패키지나 실제 레이어·디렉터리 구조를 뜻하지 않습니다.", icon=":material/info:")
    with st.container(border=True, key="card_4"):
        section_title(f"Docker 이미지: {image}", f"OS {get_meta(meta, df, 'distro')} · 매칭된 패키지 {df['package'].nunique()}개 · 매칭 {len(df)}건")
        st.plotly_chart(sankey_fig(df), use_container_width=True, config={"displayModeBar": False})
        st.caption("선의 굵기는 CVE × 패키지 매칭 건수를 나타냅니다. CVE 중복은 패키지 간 별개 매칭으로 계산됩니다.")
    st.write("")
    section_title("패키지 자세히 보기", "패키지를 선택하면 해당 패키지와 연결된 이미지·CVE만 표시합니다")
    packages = pkg_rollup(df)
    selected = st.selectbox("패키지 선택", packages["package"].drop_duplicates().tolist(), key="structure_package")
    relevant = df[df["package"] == selected].copy()
    version = ", ".join(sorted(relevant["version"].unique()))
    counts = severity_count(relevant)
    a,b,c = st.columns(3)
    with a: st.metric("패키지 버전", version)
    with b: st.metric("매칭 건수", f"{len(relevant)}건")
    with c: st.metric("고유 CVE", f"{relevant['cve'].nunique()}개")
    st.markdown("".join(f"<span class='mini-tag'><i style='background:{SEVERITY_COLORS[s]}'></i>{s} <b>{int(counts[s])}건</b></span>" for s in SEVERITIES if counts[s]), unsafe_allow_html=True)
    with st.container(border=True, key="card_chain"):
        section_title(f"이미지 → {selected} → CVE", "선택한 패키지 기준으로만 연결을 그립니다 · 취약점 매칭 관계이며 레이어 구조가 아닙니다")
        st.plotly_chart(chain_fig(relevant), use_container_width=True, config={"displayModeBar": False})
        st.caption("CVE 노드 색은 심각도입니다. 노드에 마우스를 올리면 CVSS와 Risk 값을 볼 수 있어요.")
    cols = {"cve": "CVE", "severity": "심각도", "cvss_score": "CVSS", "risk": "Risk", "fix_state": "수정 상태"}
    if relevant["image_key"].nunique() > 1:
        cols = {"image_label": "이미지", "version": "버전", **cols}
    subset = relevant[list(cols)].copy().rename(columns=cols)
    st.dataframe(severity_table(subset.sort_values("Risk", ascending=False)), use_container_width=True, hide_index=True, height=min(500, 60 + 35 * len(subset)))
    st.caption("같은 CVE가 여러 패키지에서 표시될 수 있습니다. 원본 SBOM이 추가되면 전체 패키지 목록과 파일 위치를 확장할 수 있어요.")


def explorer(df: pd.DataFrame, meta: dict, df_all: pd.DataFrame) -> None:
    page_header("취약점 상세 분석", "패키지·심각도·CVE로 검색하고 스캔 결과의 근거를 확인합니다")
    scope_bar(df, df_all)
    multi = df["image_key"].nunique() > 1
    a,b,c = st.columns([1,1,1.25])
    with a:
        severity_sel = st.multiselect("심각도", [s for s in SEVERITIES if s in set(df["severity"])], placeholder="전체 심각도")
    with b:
        pkg_sel = st.multiselect("패키지", sorted(df["package"].unique().tolist()), placeholder="전체 패키지")
    with c:
        query = st.text_input("검색", placeholder="CVE ID, 패키지명 검색")
    filtered = df.copy()
    if severity_sel:
        filtered = filtered[filtered["severity"].isin(severity_sel)]
    if pkg_sel:
        filtered = filtered[filtered["package"].isin(pkg_sel)]
    if query.strip():
        pattern = query.strip()
        filtered = filtered[filtered["cve"].str.contains(pattern, case=False, regex=False, na=False) | filtered["package"].str.contains(pattern, case=False, regex=False, na=False)]
    st.caption(f"필터 결과: 매칭 {len(filtered)}건 · 고유 CVE {filtered['cve'].nunique()}개 · 패키지 {filtered['package'].nunique()}개")
    if filtered.empty:
        st.info("검색 조건에 해당하는 결과가 없어요. 필터를 다시 선택해 주세요.")
        return
    table = filtered[(["image", "image_digest"] if multi else []) + ["cve", "package", "version", "severity", "cvss_score", "epss", "risk", "fix_state"]].copy()
    table["epss"] = (table["epss"] * 100).round(3)
    table["risk"] = table["risk"].round(4)
    table = table.rename(columns={"image": "이미지", "image_digest": "Digest", "cve": "CVE", "package": "패키지", "version": "버전", "severity": "심각도", "cvss_score": "CVSS", "epss": "EPSS (%)", "risk": "Risk", "fix_state": "수정 상태"})
    table = table.sort_values(["Risk", "CVSS"], ascending=[False, False])
    with st.container(border=True, key="card_5"):
        section_title("취약점 탐지 목록", "CVSS는 심각도 점수, EPSS는 추정 악용 가능성(%)입니다. Risk는 원본 지표입니다.")
        st.dataframe(severity_table(table), use_container_width=True, hide_index=True, height=365)
        st.download_button("현재 표 CSV 다운로드", data=table.to_csv(index=False).encode("utf-8-sig"), file_name="filtered_vulnerabilities.csv", mime="text/csv")
    st.write("")
    section_title("CVE 상세 정보", "목록에서 CVE를 선택해 어떤 이미지·패키지·버전에서 탐지되었는지 확인하세요")
    roll = cve_rollup(filtered)
    cve_selected = st.selectbox("CVE 선택", roll["cve"].tolist())
    rows = df[df["cve"] == cve_selected]
    first = rows.sort_values("risk", ascending=False, na_position="last").iloc[0]
    w,x,y,z = st.columns(4)
    with w: st.metric("심각도", str(first["severity"]))
    with x: st.metric("CVSS", f"{float(first['cvss_score']):.1f}" if pd.notna(first["cvss_score"]) else "정보 없음")
    with y: st.metric("EPSS", f"{float(first['epss'])*100:.3f}%" if pd.notna(first["epss"]) else "정보 없음")
    with z: st.metric("Risk", f"{float(first['risk']):.4f}" if pd.notna(first["risk"]) else "정보 없음")
    with st.container(border=True, key="card_where"):
        section_title("탐지 위치", f"선택 범위에서 이미지 {rows['image_key'].nunique()}개 · 패키지 {rows['package'].nunique()}개 · 매칭 {len(rows)}건")
        where = rows[["image", "image_digest", "package", "version", "severity", "cvss_score", "epss", "risk", "fix_state"]].copy()
        where["image_digest"] = where["image_digest"].map(short_digest)
        where["epss"] = where["epss"] * 100
        where = where.rename(columns={"image": "이미지", "image_digest": "Digest", "package": "패키지", "version": "버전", "severity": "심각도", "cvss_score": "CVSS", "epss": "EPSS (%)", "risk": "Risk", "fix_state": "수정 상태"})
        st.dataframe(severity_table(where), use_container_width=True, hide_index=True)
        outside = df_all[(df_all["cve"] == cve_selected) & ~df_all["image_key"].isin(df["image_key"].unique())]
        if not outside.empty:
            st.caption(f"선택 범위 밖의 다른 이미지 {outside['image_key'].nunique()}개에서도 탐지된 CVE입니다. 사이드바에서 '전체 이미지'를 선택하면 함께 볼 수 있어요.")
    with st.expander("취약점 설명 및 CVSS 벡터", expanded=True):
        st.write(str(first.get("description") or "설명이 없습니다."))
        if pd.notna(first.get("cvss_vector")) and str(first.get("cvss_vector")):
            st.code(str(first["cvss_vector"]), language=None)
    st.warning("`fix_state = unknown`은 '수정 불가'와 다릅니다. 실제 영향 여부 및 수정된 Alpine 패키지 버전은 보안 권고문과 함께 확인해야 합니다.")


def methodology(df: pd.DataFrame, meta: dict, source_name: str, df_all: pd.DataFrame) -> None:
    page_header("데이터 기준과 다음 단계", "대시보드의 해석 범위를 밝히고 향후 실제 서비스로 확장할 항목을 정리합니다")
    scope_bar(df, df_all)
    with st.container(border=True, key="card_6"):
        section_title("이번 MVP의 데이터")
        records = [
            ("입력 파일", source_name),
            ("데이터 내 이미지", f"{df_all['image_key'].nunique()}개 (이름 + digest 기준)"),
            ("분석 이미지", get_meta(meta, df, "image")),
            ("운영체제", get_meta(meta, df, "distro")),
            ("이미지 Digest", get_meta(meta, df, "image_digest")),
            ("Grype 버전", get_meta(meta, df, "grype_version")),
            ("취약점 DB 빌드", get_meta(meta, df, "db_built")),
            ("스캔 시각", get_meta(meta, df, "scanned_at")),
        ]
        rows = "".join(f"<div class='kv-k'>{html.escape(label)}</div><div class='kv-v'>{html.escape(value)}</div>" for label, value in records)
        st.markdown(f"<div class='kv'>{rows}</div>", unsafe_allow_html=True)
    st.write("")
    with st.container(border=True, key="card_7"):
        section_title("이 숫자를 어떻게 읽어야 하나요?")
        st.markdown("""
        - **매칭 30건:** (CVE, 패키지) 조합 30개입니다. 취약점 종류 30개를 뜻하지 않습니다.
        - **고유 CVE 15개:** 같은 CVE가 여러 패키지에 나타나도 한 번만 셉니다.
        - **매칭된 패키지 6개:** 전체 설치 패키지가 아닙니다. 원본 `sbom.json`이 있어야 전체 구성 대비 비율을 계산할 수 있습니다.
        - **CVSS / EPSS / Risk:** 각각 심각도 점수 / 추정 악용 가능성 / 원본에서 제공된 Risk 지표입니다. 서로 같은 단위가 아니에요.
        - **오탐 가능성:** 이번 결과는 `nvd:cpe` 방식으로 매칭되어 있으며, 실제 영향은 별도 검증해야 합니다.
        - **고정된 스캔 결과:** 새로운 취약점 DB로 재실행하면 탐지 결과가 달라질 수 있습니다. 실시간 탐지 화면이 아닙니다.
        """)
    with st.container(border=True, key="card_8"):
        section_title("다음에 추가할 기능 (확장 단계)")
        st.markdown("""
        1. `sbom.json`을 연결해 **전체 패키지 목록·패키지 위치**를 표시
        2. 여러 Docker 이미지의 스캔 결과를 받아 **이미지 간 위험도 비교**
        3. Alpine 보안 권고와 비교해 **오탐 및 실제 수정 가능한 버전 검증**
        4. 시점별 결과를 저장해 **새로 발견된 CVE / 해결된 CVE 추적**
        5. 향후 CI/CD와 연결해 배포 전에 확인하는 워크플로 구현
        """)


def main() -> None:
    st.set_page_config(page_title="SBOM Insight | 보안 모니터링", page_icon=":material/shield:", layout="wide", initial_sidebar_state="expanded")
    style()
    st.sidebar.markdown("<div class='sb-brand'><span class='sb-mark'>⬡</span>SBOM Insight</div><div class='sb-brand-sub'>DOCKER VULNERABILITY MONITORING · MVP</div><div class='sb-rule'></div>", unsafe_allow_html=True)
    nav = st.sidebar.radio("페이지 선택", PAGES, label_visibility="collapsed", width="stretch")
    st.sidebar.markdown("<div class='sb-rule'></div>", unsafe_allow_html=True)
    uploaded = st.sidebar.file_uploader("다른 데이터 ZIP 불러오기 (선택)", type=["zip"], help="matches.csv와 scan_info.json을 포함한 ZIP을 선택하세요.")
    try:
        if uploaded is not None:
            df, meta = read_zip_bytes(uploaded.getvalue())
            source_name = uploaded.name
        else:
            df, meta, source_name = load_local()
    except (FileNotFoundError, ValueError, KeyError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        st.error(f"데이터를 불러오지 못했습니다: {exc}")
        st.info("app2.py와 같은 위치에 streamlit_data_bundle.zip을 두거나, 기존 data/processed 폴더를 유지해 주세요.")
        st.stop()
    if df.empty:
        st.warning("CSV 파일에 탐지 결과가 없습니다.")
        st.stop()
    df_all = df
    images = image_options(df_all)
    labels = dict(zip(images["image_key"], images["image_label"]))
    options = ([ALL_IMAGES] if len(images) > 1 else []) + images["image_key"].tolist()
    image_sel = st.sidebar.selectbox("Docker 이미지", options, format_func=lambda k: f"전체 이미지 ({len(images)}개)" if k == ALL_IMAGES else labels[k],
                                     help="이미지 이름과 digest를 함께 기준으로 구분합니다. 선택한 이미지의 패키지·CVE만 모든 페이지에 표시됩니다.")
    if image_sel != ALL_IMAGES:
        df = df_all[df_all["image_key"] == image_sel]
    meta = scope_meta(meta, df)
    digest = get_meta(meta, df, "image_digest")
    st.sidebar.markdown(
        "<div class='sb-stats'>"
        f"<div class='sb-k'>분석 대상</div><div class='sb-v'>{html.escape(get_meta(meta, df, 'image'))}</div>"
        f"<div class='sb-k'>이미지 Digest</div><div class='sb-v'>{html.escape(short_digest(digest) + '…' if digest.startswith('sha256:') else digest)}</div>"
        f"<div class='sb-k'>스캔 DB 기준</div><div class='sb-v'>{html.escape(date_part(get_meta(meta, df, 'db_built')))}</div>"
        f"<div class='sb-k'>탐지 결과 (선택 범위)</div><div class='sb-v'>매칭 {len(df)}건 · 고유 CVE {df['cve'].nunique()}개</div>"
        + (f"<div class='sb-k'>전체 데이터</div><div class='sb-v'>이미지 {len(images)}개 · 매칭 {len(df_all)}건 · 고유 CVE {df_all['cve'].nunique()}개</div>" if len(df) != len(df_all) else "")
        + "</div>", unsafe_allow_html=True,
    )
    st.sidebar.caption("학습·중간발표용 MVP | 저장된 결과를 분석하며 실시간 관제가 아닙니다.")
    if nav == PAGES[0]:
        overview(df, meta, df_all)
    elif nav == PAGES[1]:
        structure(df, meta, df_all)
    elif nav == PAGES[2]:
        explorer(df, meta, df_all)
    else:
        methodology(df, meta, source_name, df_all)


if __name__ == "__main__":
    main()
