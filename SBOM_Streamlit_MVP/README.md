# SBOM Insight — Streamlit 중간발표 MVP

지원님의 `vulnerability_지원.json`에서 변환한 `streamlit_data_bundle.zip`을 이용하여, Docker 이미지 취약점 스캔 결과를 확인하는 대시보드입니다.

## 1. 파일 위치

현재 VS Code 프로젝트 폴더에 `app.py`만 추가해도 됩니다. 기존 Python 프로그램과 원본 JSON은 건드리지 않습니다.

```text
데이터엔지니어스_26_2/
├── app.py                         ← 추가
├── streamlit_data_bundle.zip       ← 이 파일이 있다면 바로 사용
├── data/
│   └── processed/
│       ├── matches.csv             ← 또는 기존 변환 결과 그대로 사용
│       ├── scan_info.json
│       └── streamlit_data_bundle.zip
├── vulnerability_지원.json
└── ...
```

앱은 위에서 `data/processed/streamlit_data_bundle.zip`, `streamlit_data_bundle.zip`, `data/processed/matches.csv` 순으로 데이터를 찾습니다.

## 2. 설치 및 실행 (VS Code 터미널)

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

`requirements.txt`가 없는 기존 프로젝트에 `app.py`만 복사했다면 다음과 같이 설치해도 됩니다.

```bash
python -m pip install streamlit pandas plotly
python -m streamlit run app.py
```

터미널에서 `Local URL: http://localhost:8501`이 표시되면 그 주소로 접속하세요. 종료하려면 터미널에서 `Ctrl+C`.

## 3. 화면 구성

- **전체 현황**: 매칭 30건 / 고유 CVE 15개 / High 이상 9건 / 매칭 패키지 6개, 심각도 그래프, 우선 검토 CVE, 패키지별 그래프
- **이미지 구조**: Docker 이미지 → 탐지된 패키지 → 심각도 연결 Sankey 그림과 패키지 상세 표
- **취약점 상세**: 심각도·패키지·CVE 검색, CSV 다운로드, CVSS·EPSS·원본 Risk·설명
- **분석 기준**: 이미지 Digest, Grype·DB 버전, 지표 정의, 데이터 한계, 이후 확장할 기능

## 4. 데이터 해석 시 주의

이 프로젝트에서의 '30건'은 **CVE와 패키지의 매칭 30건**이지, 서로 다른 취약점 30개가 아닙니다. 고유 CVE는 15개입니다. 그리고 패키지 6개는 **취약점이 매칭된 패키지 수**이지, 이미지 전체 구성요소 개수가 아닙니다. 전체 SBOM 또는 이미지 레이어 정보가 없으므로 구조 페이지는 실제 레이어를 표시하지 않습니다.

Grype 결과의 `fix_state`가 `unknown`이고 `nvd:cpe` 매칭이므로 CVE 목록은 우선 **검토 후보**로 해석해야 합니다. 이 MVP는 2026-10-06 취약점 DB 기반의 스냅샷으로, 실시간 스캔이나 실제 배포 차단 기능은 없습니다.

## 5. 다음 확장

지원님의 같은 스캔 버전 `sbom.json`을 추가로 확보하면, 전체 패키지 표시, 취약점 없는 패키지, 설치 구성 대비 비율 등을 만들 수 있습니다. 이후 여러 이미지와 스캔 일자를 모아 이미지 간 비교와 추세 화면으로 확장할 수 있습니다.
