package com.san.bastionpay.admin;

import com.san.bastionpay.audit.EventOutcome;
import com.san.bastionpay.audit.SecurityEvent;
import com.san.bastionpay.audit.SecurityEventEntity;
import com.san.bastionpay.audit.SecurityEventRepository;
import com.san.bastionpay.audit.SecurityEventType;
import com.san.bastionpay.auth.AuthMember;
import com.san.bastionpay.member.MemberRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 보안 대시보드 그래프: 집계가 맞는지(구간·심각도·이체·종류·IP), 관리자만 읽는지, 화면에 그래프 영역이 들어가는지. 데이터는 롤백된다. */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class SecurityChartsTest {

    @Autowired SecurityChartService charts;
    @Autowired SecurityEventRepository events;
    @Autowired MemberRepository members;
    @Autowired MockMvc mvc;

    @BeforeEach
    void emptyTable() {
        events.deleteAllInBatch();   // 이 트랜잭션 안에서만 비운다(끝나면 롤백)
    }

    private void save(SecurityEventType type, int times, String ip) {
        for (int i = 0; i < times; i++) {
            events.save(new SecurityEventEntity(SecurityEvent.of(type, EventOutcome.SUCCESS).sourceIp(ip).build()));
        }
        events.flush();
    }

    private static long sum(SecurityChartService.Series series, String key) {
        return series.datasets().stream().filter(d -> d.key().equals(key)).findFirst().orElseThrow()
                .data().stream().mapToLong(Long::longValue).sum();
    }

    private RequestPostProcessor as(String role) {
        long id = members.findByEmail(role.equals("ADMIN") ? "admin@test.com" : "test@test.com").orElseThrow().getId();
        AuthMember m = new AuthMember(id, role.equals("ADMIN") ? "관리자" : "테스터", role, "STANDARD");
        return authentication(UsernamePasswordAuthenticationToken.authenticated(m, null, m.authorities()));
    }

    @Test
    void timelineSplitsEventsBySeverityAndFillsEmptyBuckets() {
        save(SecurityEventType.LOGIN_FAILURE, 3, "203.0.113.5");     // LOW
        save(SecurityEventType.ACCOUNT_LOCKED, 1, "203.0.113.5");    // HIGH
        save(SecurityEventType.TRANSFER_COMPLETED, 2, null);         // INFO

        var data = charts.load(SecurityDashboardService.Range.DAY);

        assertThat(data.total()).isEqualTo(6);
        assertThat(data.timeline().datasets()).extracting(SecurityChartService.Dataset::key)
                .containsExactly("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL");
        assertThat(sum(data.timeline(), "INFO")).isEqualTo(2);
        assertThat(sum(data.timeline(), "LOW")).isEqualTo(3);
        assertThat(sum(data.timeline(), "MEDIUM")).isZero();
        assertThat(sum(data.timeline(), "HIGH")).isEqualTo(1);
        // 24시간은 1시간 구간이라 24~25칸이고, 모든 계열이 같은 칸 수(이벤트 없는 칸은 0)
        int buckets = data.timeline().labels().size();
        assertThat(buckets).isBetween(24, 25);
        assertThat(data.timeline().titles()).hasSize(buckets);
        data.timeline().datasets().forEach(d -> assertThat(d.data()).hasSize(buckets));
        assertThat(data.timeline().labels()).allMatch(l -> l.matches("\\d{2}시"));
    }

    @Test
    void transferSeriesGroupsOutcomes() {
        save(SecurityEventType.TRANSFER_COMPLETED, 2, null);
        save(SecurityEventType.TRANSFER_REFUNDED, 1, null);
        save(SecurityEventType.TRANSFER_NEEDS_REVIEW, 1, null);
        save(SecurityEventType.TRANSFER_REFUND_FAILED, 1, null);   // 환불까지 실패하면 검토 필요에 합친다
        save(SecurityEventType.LOGIN_FAILURE, 4, "203.0.113.5");   // 이체가 아닌 이벤트는 섞이지 않는다

        var transfers = charts.load(SecurityDashboardService.Range.DAY).transfers();

        assertThat(transfers.datasets()).extracting(SecurityChartService.Dataset::label).containsExactly("완료", "실패", "환불", "검토 필요");
        assertThat(sum(transfers, "COMPLETED")).isEqualTo(2);
        assertThat(sum(transfers, "FAILED")).isZero();
        assertThat(sum(transfers, "REFUNDED")).isEqualTo(1);
        assertThat(sum(transfers, "REVIEW")).isEqualTo(2);
    }

    @Test
    void typesKeepTheTopSixAndGroupTheRestAsOther() {
        save(SecurityEventType.LOGIN_FAILURE, 8, "203.0.113.5");
        save(SecurityEventType.ACCESS_DENIED, 7, "203.0.113.5");
        save(SecurityEventType.CSRF_REJECTED, 6, "203.0.113.5");
        save(SecurityEventType.TRANSFER_REQUESTED, 5, null);
        save(SecurityEventType.TRANSFER_COMPLETED, 4, null);
        save(SecurityEventType.TRANSFER_FAILED, 3, null);
        save(SecurityEventType.TRANSFER_REPLAY, 2, null);
        save(SecurityEventType.SESSION_EXPIRED, 1, null);

        var data = charts.load(SecurityDashboardService.Range.DAY);

        assertThat(data.typesTotal()).isEqualTo(36);
        assertThat(data.types()).hasSize(7);
        assertThat(data.types().get(0)).isEqualTo(new SecurityChartService.Slice("LOGIN_FAILURE", 8));
        assertThat(data.types().get(6)).isEqualTo(new SecurityChartService.Slice("OTHER", 3));
        assertThat(data.types().stream().mapToLong(SecurityChartService.Slice::count).sum()).isEqualTo(36);
    }

    @Test
    void failedLoginIpsAreRankedAndLimitedToEight() {
        for (int i = 1; i <= 10; i++) save(SecurityEventType.LOGIN_FAILURE, i, "203.0.113." + i);

        var ips = charts.load(SecurityDashboardService.Range.DAY).failedLoginIps();

        assertThat(ips).hasSize(8);
        assertThat(ips.get(0)).isEqualTo(new SecurityChartService.Bar("203.0.113.10", 10));
        assertThat(ips.get(7).count()).isEqualTo(3);
        assertThat(ips).extracting(SecurityChartService.Bar::count).isSortedAccordingTo(java.util.Comparator.reverseOrder());
    }

    @Test
    void weekUsesDailyBucketsAndHourUsesFiveMinuteBuckets() {
        save(SecurityEventType.LOGIN_FAILURE, 1, "203.0.113.5");

        var week = charts.load(SecurityDashboardService.Range.WEEK).timeline();
        assertThat(week.labels()).hasSizeBetween(7, 8).allMatch(l -> l.matches("\\d{2}\\.\\d{2}"));

        var hour = charts.load(SecurityDashboardService.Range.HOUR).timeline();
        assertThat(hour.labels()).hasSizeBetween(12, 13).allMatch(l -> l.matches("\\d{2}:\\d{2}"));
        assertThat(sum(hour, "LOW")).isEqualTo(1);
    }

    @Test
    void emptyPeriodGivesZerosNotErrors() {
        var data = charts.load(SecurityDashboardService.Range.DAY);

        assertThat(data.total()).isZero();
        assertThat(data.types()).isEmpty();
        assertThat(data.failedLoginIps()).isEmpty();
        assertThat(sum(data.timeline(), "INFO")).isZero();
    }

    @Test
    void onlyAdminsCanReadTheChartData() throws Exception {
        save(SecurityEventType.LOGIN_FAILURE, 2, "203.0.113.5");

        mvc.perform(get("/admin/security/charts")).andExpect(status().isUnauthorized());
        mvc.perform(get("/admin/security/charts").with(as("USER"))).andExpect(status().isForbidden());
        mvc.perform(get("/admin/security/charts").param("range", "7d").with(as("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.range").value("7d"))
                .andExpect(jsonPath("$.total").value(2))
                .andExpect(jsonPath("$.timeline.datasets.length()").value(5))
                .andExpect(jsonPath("$.failedLoginIps[0].label").value("203.0.113.5"));
    }

    @Test
    void overviewPutsTheChartsFirstAndLoadsOnlyLocalScripts() throws Exception {
        String html = mvc.perform(get("/admin/security").param("range", "1h").with(as("ADMIN")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        assertThat(html).contains("data-charts", "id=\"chart-timeline\"", "id=\"chart-transfers\"", "id=\"chart-types\"", "id=\"chart-ips\"");
        assertThat(html).contains("data-src=\"/admin/security/charts?range=1h\"");
        assertThat(html).contains("/js/vendor/chart.umd.js", "/js/admin-charts.js");
        // 그래프가 "지금 확인할 것"(검토가 필요한 이체)보다 먼저 나온다
        assertThat(html.indexOf("data-charts")).isLessThan(html.indexOf("검토가 필요한 이체"));
        // CSP 때문에 인라인 스크립트는 없다
        assertThat(List.of(html.split("<script")).stream().skip(1).allMatch(s -> s.contains("src="))).isTrue();
    }
}
