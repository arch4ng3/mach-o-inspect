#!/usr/bin/env python3

import streamlit as st
import sqlite3
import pandas as pd
import altair as alt

def load_header_data(db_path='mach_o_binaries.db'):
    """
    Load Mach-O header data into a DataFrame.
    """
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(
        """
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
        """,
        conn
    )
    conn.close()
    return df

def load_arm_instructions(db_path='mach_o_binaries.db'):
    """
    Load ARM64 instruction data into a DataFrame.
    """
    conn = sqlite3.connect(db_path)
    df_arm = pd.read_sql_query(
        """
        SELECT a.id AS instr_id,
               b.path AS binary_path,
               a.instruction
        FROM arm_asm_instructions a
        JOIN binary b ON a.binary_id = b.id
        """,
        conn
    )
    conn.close()
    return df_arm

def load_load_commands(db_path='mach_o_binaries.db'):
    """
    Load load-command data (e.g., LC_SEGMENT_64, LC_SYMTAB) into a DataFrame.
    """
    conn = sqlite3.connect(db_path)
    df_load = pd.read_sql_query(
        """
        SELECT lc.id AS load_cmd_id,
               b.path AS binary_path,
               lc.command,
               lc.cmdsize,
               lc.details
        FROM load_commands lc
        JOIN binary b ON lc.binary_id = b.id
        """,
        conn
    )
    conn.close()
    return df_load


def main():
    st.set_page_config(
        page_title="Mach-O Security Analysis",
        layout="wide",
        page_icon="🛡️",
        initial_sidebar_state="auto"
    )
    st.title("Mach-O Security Analysis Dashboard")

    # Load main header data
    df = load_header_data()
    if df.empty:
        st.warning("No Mach-O header data found.")
        return

    # Load ARM instruction data
    df_arm = load_arm_instructions()

    # =======================================================
    # MACH-O HEADER ANALYSIS
    # =======================================================
    df['flags_list'] = df['flags'].str.split()
    df_flags = df.explode('flags_list').dropna(subset=['flags_list'])

    col0, col1, col2, col3, col4, col5 = st.columns(6)
    col0.metric("Unique Binaries", str(df['binary_path'].nunique()))
    col1.metric("Total Headers", str(len(df)))
    col2.metric("CPU Types", str(df['cputype'].nunique()))
    col3.metric("File Types", str(df['filetype'].nunique()))
    col4.metric("Distinct Flags", str(df_flags['flags_list'].nunique()))
    col5.metric("Distinct Caps", str(df['caps'].nunique()))

    st.subheader("Binaries Found")
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

    # Let user choose how many flags to display
    num_top_flags = st.slider(
        "Number of Most Common Flags to Display",
        min_value=5, max_value=30, value=10, step=1
    )
    top_flags = flag_counts.head(num_top_flags)

    num_rare_flags = st.slider(
        "Number of Rarest Flags to Display",
        min_value=5, max_value=30, value=10, step=1
    )
    rare_flags = flag_counts.tail(num_rare_flags).sort_values('count', ascending=True)

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

    # Similar approach for caps
    num_top_caps = st.slider(
        "Number of Most Common Caps to Display",
        min_value=5, max_value=30, value=10, step=1,
        key="caps_top"
    )
    top_caps = caps_count.head(num_top_caps)

    num_rare_caps = st.slider(
        "Number of Rarest Caps to Display",
        min_value=5, max_value=30, value=10, step=1,
        key="caps_rare"
    )
    rare_caps = caps_count.tail(num_rare_caps).sort_values('count', ascending=True)

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
        index='filetype',
        columns='cputype',
        values='header_id',
        aggfunc='count',
        fill_value=0
    )
    st.dataframe(pivot_ftype)

    # =======================================================
    # LOAD COMMANDS ANALYSIS
    # =======================================================
    st.title("Load Commands Analysis")
    df_load = load_load_commands()

    if df_load.empty:
        st.warning("No load command data found.")
    else:
        # Summarize frequency of each load command
        df_load_freq = (
            df_load.groupby('command')
            .size()
            .reset_index(name='count')
            .sort_values('count', ascending=False)
        )

        # Sliders for top/rare load commands
        num_top_load_cmds = st.slider(
            "Number of Most Common Load Commands to Display",
            min_value=5, max_value=30, value=10, step=1
        )
        num_rare_load_cmds = st.slider(
            "Number of Rarest Load Commands to Display",
            min_value=5, max_value=30, value=10, step=1
        )

        top_load_cmds = df_load_freq.head(num_top_load_cmds)
        rare_load_cmds = df_load_freq.tail(num_rare_load_cmds).sort_values('count', ascending=True)

        col_l1, col_l2 = st.columns(2)
        with col_l1:
            st.markdown("**Most Common Load Commands**")
            top_load_cmds_chart = (
                alt.Chart(top_load_cmds)
                .mark_bar()
                .encode(
                    x=alt.X('count:Q', title='Count'),
                    y=alt.Y('command:N', sort='-x', title='Load Command')
                )
                .properties(height=300)
            )
            st.altair_chart(top_load_cmds_chart, use_container_width=True)

        with col_l2:
            st.markdown("**Rarest Load Commands**")
            rare_load_cmds_chart = (
                alt.Chart(rare_load_cmds)
                .mark_bar()
                .encode(
                    x=alt.X('count:Q', title='Count'),
                    y=alt.Y('command:N', sort='x', title='Load Command')
                )
                .properties(height=300)
            )
            st.altair_chart(rare_load_cmds_chart, use_container_width=True)

        st.subheader("Binaries Missing LC_CODE_SIGNATURE")
        # Binaries that have LC_CODE_SIGNATURE
        binaries_with_code_sig = df_load.loc[
            df_load['command'] == 'LC_CODE_SIGNATURE', 'binary_path'
        ].unique()
        # All binaries found in the load_commands table
        all_binaries_loadcmd = df_load['binary_path'].unique()

        missing_code_sig = sorted(set(all_binaries_loadcmd) - set(binaries_with_code_sig))
        st.write(f"Found {len(missing_code_sig)} binaries missing LC_CODE_SIGNATURE:")

        if missing_code_sig:
            st.table(pd.DataFrame({'binary_path': missing_code_sig}))
        else:
            st.info("All binaries have LC_CODE_SIGNATURE.")

    # =======================================================
    # ARM64 INSTRUCTION ANALYSIS
    # =======================================================
    st.title("ARM64 Instructions Analysis")

    # If no instructions, show a warning and bail out early
    if df_arm.empty:
        st.warning("No ARM64 instruction data found.")
        return

    # High-level metrics
    total_instructions = len(df_arm)  # total rows
    distinct_instructions = df_arm['instruction'].nunique()
    distinct_binaries_with_instructions = df_arm['binary_path'].nunique()

    colA, colB, colC = st.columns(3)
    colA.metric("Total ARM64 Instructions Logged", str(total_instructions))
    colB.metric("Distinct Instruction Mnemonics", str(distinct_instructions))
    colC.metric("Binaries with ARM64 Instructions", str(distinct_binaries_with_instructions))

    # Frequency of instructions
    df_arm_freq = (
        df_arm.groupby('instruction')
        .size()
        .reset_index(name='count')
        .sort_values('count', ascending=False)
    )

    # Add sliders so we can control how many instructions to display
    num_top_instructions = st.slider(
        "Number of Most Common Instructions to Display",
        min_value=10, max_value=50, value=10, step=1
    )
    num_rare_instructions = st.slider(
        "Number of Rarest Instructions to Display",
        min_value=10, max_value=50, value=10, step=1
    )

    top_instructions = df_arm_freq.head(num_top_instructions)
    rare_instructions = df_arm_freq.tail(num_rare_instructions).sort_values('count', ascending=True)

    st.subheader("ARM64 Instruction Distribution")
    col7, col8 = st.columns(2)
    with col7:
        st.markdown("**Most Common Instructions**")
        top_instr_chart = (
            alt.Chart(top_instructions)
            .mark_bar()
            .encode(
                x=alt.X('count:Q', title='Count'),
                y=alt.Y('instruction:N', sort='-x', title='Instruction')
            )
            .properties(height=400)   # Increase chart height as desired
        )
        st.altair_chart(top_instr_chart, use_container_width=True)

    with col8:
        st.markdown("**Rarest Instructions**")
        rare_instr_chart = (
            alt.Chart(rare_instructions)
            .mark_bar()
            .encode(
                x=alt.X('count:Q', title='Count'),
                y=alt.Y('instruction:N', sort='x', title='Instruction')
            )
            .properties(height=400)   # Increase chart height as desired
        )
        st.altair_chart(rare_instr_chart, use_container_width=True)

    st.subheader("ARM64 Instructions - Sample Data")
    st.dataframe(df_arm.sample(min(len(df_arm), 50)))  # show up to 50 random rows


if __name__ == "__main__":
    main()
