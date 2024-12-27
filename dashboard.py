#!/usr/bin/env python3

import streamlit as st
import sqlite3
import pandas as pd
import altair as alt

def load_data(db_path='mach_o_binaries.db'):
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("""
        SELECT h.id AS header_id,
               b.path AS binary_path,
               h.magic,
               h.cputype,
               h.cpusubtype,
               h.caps,
               h.filetype,
               h.ncmds,
               h.sizeofcmds,
               h.flags
        FROM binary_header h
        JOIN binary b ON h.binary_id = b.id
    """, conn)
    conn.close()
    return df

def main():
    st.set_page_config(
        page_title="Mach-O Security Analysis",
        layout="wide",
        page_icon="🛡️",
        initial_sidebar_state="auto"
    )
    st.title("Mach-O Security Analysis Dashboard")

    df = load_data()
    if df.empty:
        st.warning("No data found.")
        return

    df['flags_list'] = df['flags'].str.split()
    df_flags = df.explode('flags_list').dropna(subset=['flags_list'])

    col0, col1, col2, col3, col4, col5 = st.columns(6)
    col0.metric("Unique Binaries", str(df['binary_path'].nunique()))
    col1.metric("Total Headers", str(len(df)))
    col2.metric("CPU Types", str(df['cputype'].nunique()))
    col3.metric("File Types", str(df['filetype'].nunique()))
    col4.metric("Distinct Flags", str(df_flags['flags_list'].nunique()))
    col5.metric("Distinct Caps", str(df['caps'].nunique()))

    st.subheader("Binaries found")
    df_display = df.drop(columns=['flags_list'], errors='ignore')
    st.dataframe(df_display)

    st.subheader("Flags Analysis")
    flag_counts = (
        df_flags
        .groupby('flags_list')['header_id']
        .count()
        .reset_index(name='count')
        .sort_values('count', ascending=False)
    )
    top_flags = flag_counts.head(10)
    rare_flags = flag_counts.tail(10).sort_values('count', ascending=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Most Common Flags**")
        top_chart = (
            alt.Chart(top_flags)
            .mark_bar()
            .encode(
                x=alt.X('count:Q', title='Count'),
                y=alt.Y('flags_list:N', sort='-x', title='Flag')
            )
            .properties(height=300)
        )
        st.altair_chart(top_chart, use_container_width=True)

    with c2:
        st.markdown("**Rarest Flags**")
        rare_chart = (
            alt.Chart(rare_flags)
            .mark_bar()
            .encode(
                x=alt.X('count:Q', title='Count'),
                y=alt.Y('flags_list:N', sort='x', title='Flag')
            )
            .properties(height=300)
        )
        st.altair_chart(rare_chart, use_container_width=True)

    st.subheader("Caps Analysis")
    caps_count = (
        df.groupby('caps')['header_id']
        .count()
        .reset_index(name='count')
        .sort_values('count', ascending=False)
    )
    top_caps = caps_count.head(10)
    rare_caps = caps_count.tail(10).sort_values('count', ascending=True)

    c3, c4 = st.columns(2)
    with c3:
        st.markdown("**Most Common Caps**")
        top_caps_chart = (
            alt.Chart(top_caps)
            .mark_bar()
            .encode(
                x=alt.X('count:Q', title='Count'),
                y=alt.Y('caps:N', sort='-x', title='Caps')
            )
            .properties(height=300)
        )
        st.altair_chart(top_caps_chart, use_container_width=True)

    with c4:
        st.markdown("**Rarest Caps**")
        rare_caps_chart = (
            alt.Chart(rare_caps)
            .mark_bar()
            .encode(
                x=alt.X('count:Q', title='Count'),
                y=alt.Y('caps:N', sort='x', title='Caps')
            )
            .properties(height=300)
        )
        st.altair_chart(rare_caps_chart, use_container_width=True)

    st.subheader("Load Commands (ncmds)")
    fewest_ncmds = df[['binary_path', 'ncmds']].sort_values('ncmds', ascending=True).head(10)
    most_ncmds = df[['binary_path', 'ncmds']].sort_values('ncmds', ascending=False).head(10)
    c5, c6 = st.columns(2)
    with c5:
        st.markdown("**Fewest Load Commands**")
        st.table(fewest_ncmds)
    with c6:
        st.markdown("**Most Load Commands**")
        st.table(most_ncmds)

    st.subheader("Filetype vs. CPU Type")
    pivot_ftype = df.pivot_table(
        index='filetype', columns='cputype', values='header_id', aggfunc='count', fill_value=0
    )
    st.dataframe(pivot_ftype)

if __name__ == "__main__":
    main()