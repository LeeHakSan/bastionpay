package com.san.bastionpay.admin;

import com.san.bastionpay.audit.SecurityEventRepository;
import com.san.bastionpay.audit.SecurityEventType;
import com.san.bastionpay.audit.Severity;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 보안 대시보드 그래프용 집계. security_event 를 읽기만 한다. 시간 구간은 한국 시간 경계로 나누고,
 * 이벤트가 없는 구간도 0 으로 채워서 그래프에 빈 칸이 생기지 않게 한다.
 */
@Service
@Transactional(readOnly = true)
public class SecurityChartService {

    /** 한 줄(데이터 계열). key 는 색을 정하는 데 쓰고, label 은 범례에 보인다. */
    public record Dataset(String key, String label, List<Long> data) {}

    /** 시간 구간별 계열들. labels 는 축 눈금, titles 는 툴팁 제목(날짜까지), starts 는 각 구간의 시작 시각(UTC epoch 초). */
    public record Series(List<String> labels, List<String> titles, List<Long> starts, List<Dataset> datasets) {}

    public record Slice(String key, long count) {}

    public record Bar(String label, long count) {}

    public record ChartData(String range, String rangeLabel, long total, Series timeline, Series transfers, List<Slice> types,
                            long typesTotal, List<Bar> failedLoginIps) {}

    private static final ZoneId KST = ZoneId.of("Asia/Seoul");
    private static final long KST_OFFSET_SECONDS = 9 * 3600L;
    private static final int TOP_TYPES = 6;
    private static final int TOP_IPS = 8;

    /** 이체 결과 그래프에 쓰는 이벤트 → (계열 이름, 범례). 같은 계열에 여러 종류가 모일 수 있다. */
    private static final Map<SecurityEventType, String> TRANSFER_SERIES = new EnumMap<>(SecurityEventType.class);
    private static final Map<String, String> TRANSFER_LABELS = new LinkedHashMap<>();

    static {
        TRANSFER_SERIES.put(SecurityEventType.TRANSFER_COMPLETED, "COMPLETED");
        TRANSFER_SERIES.put(SecurityEventType.TRANSFER_FAILED, "FAILED");
        TRANSFER_SERIES.put(SecurityEventType.TRANSFER_REFUNDED, "REFUNDED");
        TRANSFER_SERIES.put(SecurityEventType.TRANSFER_NEEDS_REVIEW, "REVIEW");
        TRANSFER_SERIES.put(SecurityEventType.TRANSFER_REFUND_FAILED, "REVIEW");
        TRANSFER_LABELS.put("COMPLETED", "완료");
        TRANSFER_LABELS.put("FAILED", "실패");
        TRANSFER_LABELS.put("REFUNDED", "환불");
        TRANSFER_LABELS.put("REVIEW", "검토 필요");
    }

    private final SecurityEventRepository events;

    public SecurityChartService(SecurityEventRepository events) {
        this.events = events;
    }

    public ChartData load(SecurityDashboardService.Range range) {
        return load(range, Instant.now());
    }

    ChartData load(SecurityDashboardService.Range range, Instant now) {
        LocalDateTime since = LocalDateTime.ofInstant(now.minus(range.duration()), ZoneOffset.UTC);
        long sec = bucketSeconds(range);
        long first = Math.floorDiv(now.minus(range.duration()).getEpochSecond() + KST_OFFSET_SECONDS, sec);
        long last = Math.floorDiv(now.getEpochSecond() + KST_OFFSET_SECONDS, sec);
        int size = (int) (last - first + 1);

        // 구간 × 심각도, 구간 × 이체 결과
        Map<Severity, long[]> bySeverity = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) bySeverity.put(s, new long[size]);
        Map<String, long[]> byTransfer = new LinkedHashMap<>();
        TRANSFER_LABELS.keySet().forEach(k -> byTransfer.put(k, new long[size]));
        long total = 0;
        for (var row : events.countByBucket(since, sec, KST_OFFSET_SECONDS)) {
            int i = (int) (row.getBucket().longValue() - first);
            if (i < 0 || i >= size) continue;
            Severity severity = parse(Severity.class, row.getSeverity());
            if (severity != null) bySeverity.get(severity)[i] += row.getCnt();
            total += row.getCnt();
            SecurityEventType type = parse(SecurityEventType.class, row.getType());
            String series = type == null ? null : TRANSFER_SERIES.get(type);
            if (series != null) byTransfer.get(series)[i] += row.getCnt();
        }

        List<String> labels = new ArrayList<>(size);
        List<String> titles = new ArrayList<>(size);
        List<Long> starts = new ArrayList<>(size);
        for (long b = first; b <= last; b++) {
            starts.add(b * sec - KST_OFFSET_SECONDS);
            var start = Instant.ofEpochSecond(b * sec - KST_OFFSET_SECONDS).atZone(KST);
            labels.add(start.format(labelFormat(range)));
            titles.add(start.format(DateTimeFormatter.ofPattern(sec >= 86400 ? "MM.dd" : "MM.dd HH:mm")));
        }

        List<Dataset> severities = new ArrayList<>();
        for (Severity s : Severity.values()) severities.add(new Dataset(s.name(), s.name(), toList(bySeverity.get(s))));
        List<Dataset> transfers = new ArrayList<>();
        byTransfer.forEach((k, v) -> transfers.add(new Dataset(k, TRANSFER_LABELS.get(k), toList(v))));

        // 이벤트 종류별 비율: 많은 6개 + 나머지는 기타로 묶는다
        var typeCounts = events.countByType(since);
        long typesTotal = typeCounts.stream().mapToLong(SecurityEventRepository.TypeCount::getCnt).sum();
        List<Slice> slices = new ArrayList<>();
        long rest = 0;
        for (int i = 0; i < typeCounts.size(); i++) {
            var c = typeCounts.get(i);
            if (i < TOP_TYPES) slices.add(new Slice(c.getType().name(), c.getCnt()));
            else rest += c.getCnt();
        }
        if (rest > 0) slices.add(new Slice("OTHER", rest));

        List<Bar> ips = events.topSourceIps(SecurityEventType.LOGIN_FAILURE, since, PageRequest.of(0, TOP_IPS)).stream()
                .map(c -> new Bar(c.getItem(), c.getCnt())).toList();

        return new ChartData(range.code(), range.label(), total, new Series(labels, titles, starts, severities),
                new Series(labels, titles, starts, transfers), slices, typesTotal, ips);
    }

    /** 이체 결과 계열(COMPLETED·FAILED·REFUNDED·REVIEW) 하나에 속한 이벤트 종류. 모르는 계열이면 비어 있다. */
    static java.util.Set<SecurityEventType> transferTypes(String series) {
        var out = java.util.EnumSet.noneOf(SecurityEventType.class);
        TRANSFER_SERIES.forEach((type, key) -> { if (key.equals(series)) out.add(type); });
        return out;
    }

    /** 이체 결과 그래프에 쓰는 모든 이벤트 종류. */
    static java.util.Set<SecurityEventType> allTransferTypes() {
        return java.util.EnumSet.copyOf(TRANSFER_SERIES.keySet());
    }

    static String transferLabel(String series) {
        return TRANSFER_LABELS.get(series);
    }

    static boolean isTransferSeries(String series) {
        return TRANSFER_LABELS.containsKey(series);
    }

    /** 종류별 비율에서 이름이 따로 나오는 상위 종류(나머지는 "기타"). */
    List<SecurityEventType> topTypes(SecurityDashboardService.Range range) {
        LocalDateTime since = LocalDateTime.now(ZoneOffset.UTC).minus(range.duration());
        return events.countByType(since).stream().limit(TOP_TYPES).map(SecurityEventRepository.TypeCount::getType).toList();
    }

    /** 구간 시작 시각(UTC epoch 초)을 화면에 보이는 한국 시간 문구로. */
    static String bucketTitle(SecurityDashboardService.Range range, long startEpochSecond) {
        var start = Instant.ofEpochSecond(startEpochSecond).atZone(KST);
        long sec = bucketSeconds(range);
        return start.format(DateTimeFormatter.ofPattern(sec >= 86400 ? "MM.dd" : sec >= 3600 ? "MM.dd HH시" : "MM.dd HH:mm"));
    }

    /** 1시간은 5분, 24시간은 1시간, 7일은 하루 단위. */
    static long bucketSeconds(SecurityDashboardService.Range range) {
        return switch (range) {
            case HOUR -> 300;
            case DAY -> 3600;
            case WEEK -> 86400;
        };
    }

    private static DateTimeFormatter labelFormat(SecurityDashboardService.Range range) {
        return switch (range) {
            case HOUR -> DateTimeFormatter.ofPattern("HH:mm");
            case DAY -> DateTimeFormatter.ofPattern("HH시");
            case WEEK -> DateTimeFormatter.ofPattern("MM.dd");
        };
    }

    private static <E extends Enum<E>> E parse(Class<E> type, String value) {
        try {
            return value == null ? null : Enum.valueOf(type, value);
        } catch (IllegalArgumentException e) {
            return null;   // 알 수 없는 값은 그래프에서만 뺀다
        }
    }

    private static List<Long> toList(long[] values) {
        List<Long> out = new ArrayList<>(values.length);
        for (long v : values) out.add(v);
        return out;
    }
}
