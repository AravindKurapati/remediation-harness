package com.example.orders;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Order lookups for the clearing portfolio.
 *
 * DELIBERATELY VULNERABLE. This is a demo target for the remediation harness, not
 * example code. The findings the harness reports against this file are real.
 */
public class OrderRepository {

    private final Connection conn;

    public OrderRepository(Connection conn) {
        this.conn = conn;
    }

    /** FINDING: SQL injection (CWE-89). The counterparty name is concatenated in. */
    public List<String> findByCounterparty(String counterparty) throws Exception {
        String query = "SELECT ref FROM orders WHERE counterparty = '" + counterparty + "'";
        List<String> out = new ArrayList<>();
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(query)) {
            while (rs.next()) {
                out.add(rs.getString("ref"));
            }
        }
        return out;
    }

    /** FINDING: SQL injection (CWE-89), identifier position. A placeholder cannot fix this. */
    public List<String> listSorted(String sortColumn) throws Exception {
        String query = "SELECT ref FROM orders ORDER BY " + sortColumn;
        List<String> out = new ArrayList<>();
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(query)) {
            while (rs.next()) {
                out.add(rs.getString("ref"));
            }
        }
        return out;
    }
}
