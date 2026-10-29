package com.san.bastionpay.admin;

import com.san.bastionpay.app.Pager;
import com.san.bastionpay.audit.SecurityEventType;
import com.san.bastionpay.audit.Severity;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 그래프 상세 화면: 개요의 그래프 하나를 크게 보여 주고, 그 그래프가 센 이벤트를 아래에 10건씩 나열한다.
 * 막대·조각을 누르면 그 조건(시간 구간·심각도·이체 결과·이벤트 종류·IP)으로 목록이 걸러진다.
 * 잘못된 조건 값은 오류 없이 무시하고 전체를 보여 준다.
 */
@Controller
@RequestMapping("/admin/security/graph")
@PreAuthorize("hasRole('ADMIN')")
public class AdminGraphController {

    /** 그래프 종류. path 는 주소에 쓰는 이름이다. */
    public enum Kind {
        TIMELINE("timeline", "이벤트 추이", "시간 구간별 이벤트를 심각도별로 쌓은 그래프입니다. 막대를 누르면 그 시간대·심각도의 이벤트만 아래에 나옵니다."),
        TRANSFERS("transfers", "이체 결과 추이", "시간 구간별 이체 결과(완료·실패·환불·검토 필요)입니다. 막대를 누르면 그 시간대·결과의 이벤트만 아래에 나옵니다."),
        TYPES("types", "이벤트 종류별 비율", "기간 안의 이벤트를 종류별로 나눈 비율입니다. 조각을 누르면 그 종류의 이벤트만 아래에 나옵니다."),
        IPS("ips", "로그인 실패 상위 IP", "로그인 실패가 많은 출발지 IP입니다. 막대를 누르면 그 IP의 로그인 실패 이벤트만 아래에 나옵니다.");

        private final String path;
        private final String title;
        private final String description;

        Kind(String path, String title, String description) {
            this.path = path;
            this.title = title;
            this.description = description;
        }

        public String path() { return path; }
        public String title() { return title; }
        public String description() { return description; }

        static Kind of(String path) {
            for (Kind k : values()) if (k.path.equals(path)) return k;
            return null;
        }
    }

    private final SecurityChartService charts;
    private final SecurityEventSearchService search;

    public AdminGraphController(SecurityChartService charts, SecurityEventSearchService search) {
        this.charts = charts;
        this.search = search;
    }

    @GetMapping("/{kind}")
    public String page(@PathVariable String kind, @RequestParam(defaultValue = "24h") String range, @RequestParam(required = false) String from,
                       @RequestParam(required = false) String series, @RequestParam(required = false) String type,
                       @RequestParam(required = false) String ip, @RequestParam(defaultValue = "1") int page, Model model) {
        Kind k = Kind.of(kind);
        if (k == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        var r = SecurityDashboardService.Range.of(range);

        // 선택 조건(모두 선택 사항). 그래프 종류에 맞는 것만 받아들인다
        Long start = null;
        String seriesKey = null;
        String typeKey = null;
        String ipKey = null;
        List<String> tags = new ArrayList<>();
        Instant windowFrom = null;
        Instant windowTo = null;
        Severity severity = null;
        Set<SecurityEventType> types = null;
        Set<SecurityEventType> exclude = null;

        if (k == Kind.TIMELINE || k == Kind.TRANSFERS) {
            start = epoch(from);
            if (start != null) {
                windowFrom = Instant.ofEpochSecond(start);
                windowTo = windowFrom.plusSeconds(SecurityChartService.bucketSeconds(r));
                tags.add(SecurityChartService.bucketTitle(r, start));
            }
        }
        if (k == Kind.TIMELINE) {
            severity = AdminParams.enumOf(Severity.class, series);
            if (severity != null) { seriesKey = severity.name(); tags.add(seriesKey); }
        } else if (k == Kind.TRANSFERS) {
            types = SecurityChartService.allTransferTypes();
            if (series != null && SecurityChartService.isTransferSeries(series)) {
                seriesKey = series;
                types = SecurityChartService.transferTypes(series);
                tags.add(SecurityChartService.transferLabel(series));
            }
        } else if (k == Kind.TYPES) {
            if ("OTHER".equals(type)) {
                typeKey = "OTHER";
                exclude = Set.copyOf(charts.topTypes(r));
                tags.add("기타(상위 6개 종류 외)");
            } else {
                var evType = AdminParams.enumOf(SecurityEventType.class, type);
                if (evType != null) { typeKey = evType.name(); types = Set.of(evType); tags.add(typeKey); }
            }
        } else {
            types = Set.of(SecurityEventType.LOGIN_FAILURE);
            var normalized = ip == null || ip.isBlank() ? java.util.Optional.<String>empty() : AdminParams.ip(ip);
            if (normalized.isPresent()) { ipKey = normalized.get(); tags.add(ipKey); }
        }

        var result = search.searchBy(new SecurityEventSearchService.Criteria(r, windowFrom, windowTo, severity, types, exclude, ipKey), page);

        Map<String, String> keep = new LinkedHashMap<>();
        keep.put("range", r.code());
        keep.put("from", start == null ? null : String.valueOf(start));
        keep.put("series", seriesKey);
        keep.put("type", typeKey);
        keep.put("ip", ipKey);
        String base = "/admin/security/graph/" + k.path();

        model.addAttribute("kind", k);
        model.addAttribute("result", result);
        model.addAttribute("pager", Pager.of(result.page(), result.totalPages(), p -> AdminParams.href(base, keep, p)));
        model.addAttribute("ranges", SecurityDashboardService.Range.values());
        model.addAttribute("range", r.code());
        model.addAttribute("rangeLabel", r.label());
        model.addAttribute("selFrom", start);
        model.addAttribute("selSeries", seriesKey);
        model.addAttribute("selType", typeKey);
        model.addAttribute("selIp", ipKey);
        model.addAttribute("tags", tags);
        model.addAttribute("activeNav", "admin");
        model.addAttribute("tab", "overview");
        return "admin/graph";
    }

    /** 구간 시작 시각(UTC epoch 초). 숫자가 아니거나 말이 안 되는 값은 없는 것으로 본다. */
    private static Long epoch(String value) {
        if (value == null || !value.matches("\\d{1,11}")) return null;
        long v = Long.parseLong(value);
        return v > 0 && v < 4_102_444_800L ? v : null;
    }
}
