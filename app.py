"""Titan.Log event preview. Run from the repo root: streamlit run app.py."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ingest import load_dir

DATA_DIR = ROOT / "data" / "otrf"

st.set_page_config(page_title="Titan.Log", layout="wide")
st.title("Titan.Log")


@st.cache_data(show_spinner=False)
def _load(directory: str) -> pd.DataFrame:
    return load_dir(directory)


frame = _load(str(DATA_DIR))
file_count = int(frame["source_file"].nunique()) if len(frame) else 0

counts = st.columns(2)
counts[0].metric("total_events", len(frame))
counts[1].metric("files", file_count)

if frame.empty:
    st.info("No events loaded.")
else:
    st.dataframe(frame.head(50))
