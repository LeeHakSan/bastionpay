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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 그래프 상세 화면: 관리자만 열 수 있는지, 막대·조각을 누른 조건으로 목록이 걸러지는지, 잘못된 조건은 무시하는지. 데이터는 롤백된다. */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class GraphDetailTest {

    @Autowired MockMvc mvc;
    @Autowired SecurityEventRepository events;
    @Autowired SecurityChartService charts;
    @Autowired MemberRepository members;

    @BeforeEach
    void emptyTable() {
        events.deleteAllInBatch();
    }

    private void save(SecurityEventType type, int times, String ip) {
        for (int i = 0; i < times; i++) {
            events.save(new SecurityEventEntity(SecurityEvent.of(type, EventOutcome.SUCCESS).sourceIp(ip).build()));
        }
        events.flush();
    }

    private RequestPostProcessor as(String role) {
        long id = members.findByEmail(role.equals("ADMIN") ? "admin@test.com" : "test@test.com").orElseThrow().getId();
        AuthMember m = new AuthMember(id, role.equals("ADMIN") ? "관리자" : "테스터", role, "STANDARD");
        return authentication(UsernamePasswordAuthenticationToken.authenticated(m, null, m.authorities()));
    }

    private String page(String path, String... params) throws Exception {
        var req = get(path).with(as("ADMIN"));
        for (int i = 0; i < params.length; i += 2) req = req.param(params[i], params[i + 1]);
        return mvc.perform(req).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    }

    /** 현재 시간 구간의 시작 시각(UTC epoch 초). 방금 저장한 이벤트가 들어 있는 구간이다. */
    private long currentBucket(SecurityDashboardService.Range range) {
        var starts = charts.load(range).timeline().starts();
        return starts.get(starts.size() - 1);
    }

    @Test
    void onlyAdminsCanOpenTheGraphPagesAndUnknownGraphsAre404() throws Exception {
        mvc.perform(get("/admin/security/graph/timeline")).andExpect(status().isUnauthorized());
        mvc.perform(get("/admin/security/graph/timeline").with(as("USER"))).andExpect(status().isForbidden());
        mvc.perform(get("/admin/security/graph/timeline").with(as("ADMIN"))).andExpect(status().isOk());
        mvc.perform(get("/admin/security/graph/nothing").with(as("ADMIN"))).andExpect(status().isNotFound());
    }

    @Test
    void everyGraphKindOpensWithTheBigChartAndTheEventList() throws Exception {
        save(SecurityEventType.LOGIN_FAILURE, 2, "203.0.113.5");
        for (String kind : new String[]{"timeline", "transfers", "types", "ips"}) {
            String html = page("/admin/security/graph/" + kind, "range", "7d");
            assertThat(html).contains("data-mode=\"detail\"", "data-kind=\"" + kind + "\"", "id=\"chart-" + kind + "\"",
                    "data-src=\"/admin/security/charts?range=7d\"", "/js/vendor/chart.umd.js", "/js/admin-charts.js", "이 그래프의 이벤트", "개요로 돌아가기");
        }
    }

    @Test
    void timelineFiltersByTheClickedBucketAndSeverity() throws Exception {
        save(SecurityEventType.LOGIN_FAILURE, 2, "203.0.113.5");    // LOW
        save(SecurityEventType.ACCOUNT_LOCKED, 1, "203.0.113.5");   // HIGH
        long bucket = currentBucket(SecurityDashboardService.Range.DAY);

        String all = page("/admin/security/graph/timeline", "range", "24h");
        assertThat(all).contains("LOGIN_FAILURE", "ACCOUNT_LOCKED", "3건");

        String high = page("/admin/security/graph/timeline", "range", "24h", "from", String.valueOf(bucket), "series", "HIGH");
        assertThat(high).contains("ACCOUNT_LOCKED", "1건", "선택한 조건", "선택 해제").doesNotContain("LOGIN_FAILURE");
        assertThat(high).contains("data-sel-from=\"" + bucket + "\"", "data-sel-series=\"HIGH\"");

        // 이벤트가 없는 시간 구간을 고르면 목록이 비고 안내가 나온다
        String other = page("/admin/security/graph/timeline", "range", "24h", "from", String.valueOf(bucket - 7200), "series", "HIGH");
        assertThat(other).contains("조건에 맞는 이벤트가 없습니다").doesNotContain("ACCOUNT_LOCKED");
    }

    @Test
    void transfersFilterByOutcomeAndOnlyShowTransferEvents() throws Exception {
        save(SecurityEventType.TRANSFER_COMPLETED, 2, null);
        save(SecurityEventType.TRANSFER_REFUNDED, 1, null);
        save(SecurityEventType.TRANSFER_NEEDS_REVIEW, 1, null);
        save(SecurityEventType.TRANSFER_REFUND_FAILED, 1, null);
        save(SecurityEventType.LOGIN_FAILURE, 3, "203.0.113.5");

        String all = page("/admin/security/graph/transfers", "range", "24h");
        assertThat(all).contains("5건").doesNotContain("LOGIN_FAILURE");

        String review = page("/admin/security/graph/transfers", "range", "24h", "series", "REVIEW");
        assertThat(review).contains("2건", "TRANSFER_NEEDS_REVIEW", "TRANSFER_REFUND_FAILED", "검토 필요").doesNotContain("TRANSFER_COMPLETED");
    }

    @Test
    void typesFilterBySliceAndOtherMeansEverythingOutsideTheTopSix() throws Exception {
        save(SecurityEventType.LOGIN_FAILURE, 8, "203.0.113.5");
        save(SecurityEventType.ACCESS_DENIED, 7, "203.0.113.5");
        save(SecurityEventType.CSRF_REJECTED, 6, "203.0.113.5");
        save(SecurityEventType.TRANSFER_REQUESTED, 5, null);
        save(SecurityEventType.TRANSFER_COMPLETED, 4, null);
        save(SecurityEventType.TRANSFER_FAILED, 3, null);
        save(SecurityEventType.TRANSFER_REPLAY, 2, null);
        save(SecurityEventType.SESSION_EXPIRED, 1, null);

        String one = page("/admin/security/graph/types", "range", "24h", "type", "LOGIN_FAILURE");
        assertThat(one).contains("8건").doesNotContain("ACCESS_DENIED");

        String rest = page("/admin/security/graph/types", "range", "24h", "type", "OTHER");
        assertThat(rest).contains("3건", "기타", "TRANSFER_REPLAY", "SESSION_EXPIRED").doesNotContain("LOGIN_FAILURE", "TRANSFER_FAILED");
    }

    @Test
    void ipsShowOnlyLoginFailuresOfTheClickedIp() throws Exception {
        save(SecurityEventType.LOGIN_FAILURE, 3, "203.0.113.5");
        save(SecurityEventType.LOGIN_FAILURE, 2, "203.0.113.6");
        save(SecurityEventType.ACCESS_DENIED, 4, "203.0.113.5");   // 로그인 실패가 아니라서 이 그래프에는 없다

        String ip = page("/admin/security/graph/ips", "range", "24h", "ip", "203.0.113.5");
        assertThat(ip).contains("3건", "203.0.113.5").doesNotContain("203.0.113.6", "ACCESS_DENIED");
        assertThat(page("/admin/security/graph/ips", "range", "24h")).contains("5건");
    }

    @Test
    void badConditionsAreIgnoredWithoutErrors() throws Exception {
        save(SecurityEventType.LOGIN_FAILURE, 1, "203.0.113.5");
        String html = page("/admin/security/graph/timeline", "range", "nope", "from", "abc", "series", "WRONG", "type", "x", "ip", "y", "page", "999");
        assertThat(html).contains("1건").doesNotContain("선택 해제");
        assertThat(page("/admin/security/graph/ips", "ip", "not-an-ip", "from", "-5")).contains("1건");
    }

    @Test
    void overviewLinksEachGraphToItsDetailPage() throws Exception {
        String html = page("/admin/security", "range", "7d");
        for (String kind : new String[]{"timeline", "transfers", "types", "ips"}) {
            assertThat(html).contains("href=\"/admin/security/graph/" + kind + "?range=7d\"", "data-detail=\"/admin/security/graph/" + kind + "?range=7d\"");
        }
    }

    @Test
    void chartSeriesStartsAreConsecutiveBucketBoundaries() {
        var timeline = charts.load(SecurityDashboardService.Range.DAY).timeline();
        assertThat(timeline.starts()).hasSameSizeAs(timeline.labels());
        for (int i = 1; i < timeline.starts().size(); i++) {
            assertThat(timeline.starts().get(i) - timeline.starts().get(i - 1)).isEqualTo(3600L);
        }
    }
}
