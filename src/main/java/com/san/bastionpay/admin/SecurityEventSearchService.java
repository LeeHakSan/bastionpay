package com.san.bastionpay.admin;

import com.san.bastionpay.audit.EventOutcome;
import com.san.bastionpay.audit.SecurityEventEntity;
import com.san.bastionpay.audit.SecurityEventRepository;
import com.san.bastionpay.audit.SecurityEventType;
import com.san.bastionpay.audit.Severity;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/** 이벤트 탭의 검색: 기간·분류·종류·심각도·결과·출발지 IP·회원으로 걸러 10건씩 본다. */
@Service
@Transactional(readOnly = true)
public class SecurityEventSearchService {

    /** 심각도 필터에서 "높음 이상"(HIGH·CRITICAL)을 뜻하는 값. */
    public static final String HIGH_PLUS = "HIGH_PLUS";

    /**
     * @param category 비우면 전체. 종류(type)를 고르면 종류가 우선한다
     * @param severity 비우면 전체, HIGH_PLUS 면 높음 이상, 아니면 Severity 이름
     * @param ip       이미 정규화한 IP(비우면 전체)
     */
    public record Filter(SecurityDashboardService.Range range, SecurityEventType.Category category, SecurityEventType type, String severity,
                         EventOutcome outcome, String ip, Long memberId) {}

    private final SecurityEventRepository events;

    public SecurityEventSearchService(SecurityEventRepository events) {
        this.events = events;
    }

    /**
     * 그래프 상세 화면의 검색. 그래프가 센 이벤트를 그대로 보여 주기 위한 조건이다.
     * @param from 시간 구간의 시작(포함)·끝(미포함). 둘 다 비우면 기간 전체
     * @param types 비우면 모든 종류
     * @param excludeTypes 이 종류는 뺀다(종류별 비율의 "기타")
     */
    public record Criteria(SecurityDashboardService.Range range, Instant from, Instant to, Severity severity,
                           Collection<SecurityEventType> types, Collection<SecurityEventType> excludeTypes, String ip) {}

    public PagedList<SecurityDashboardService.EventRow> search(Filter f, int page) {
        return paged(spec(f), page);
    }

    public PagedList<SecurityDashboardService.EventRow> searchBy(Criteria c, int page) {
        return paged(spec(c), page);
    }

    private PagedList<SecurityDashboardService.EventRow> paged(Specification<SecurityEventEntity> spec, int page) {
        var paging = PageRequest.of(Math.max(page, 1) - 1, PagedList.PAGE_SIZE, Sort.by(Sort.Direction.DESC, "id"));
        var result = events.findAll(spec, paging);
        // 마지막 쪽을 넘어서면 마지막 쪽으로 맞춘다
        if (result.getTotalPages() > 0 && page > result.getTotalPages()) {
            result = events.findAll(spec, PageRequest.of(result.getTotalPages() - 1, PagedList.PAGE_SIZE, Sort.by(Sort.Direction.DESC, "id")));
        }
        return new PagedList<>(result.getContent().stream().map(SecurityDashboardService::toRow).toList(), result.getNumber() + 1,
                Math.max(1, result.getTotalPages()), result.getTotalElements());
    }

    static Specification<SecurityEventEntity> spec(Criteria c) {
        return (root, query, cb) -> {
            List<Predicate> ps = new ArrayList<>();
            ps.add(cb.greaterThanOrEqualTo(root.get("occurredAt"), LocalDateTime.now(ZoneOffset.UTC).minus(c.range().duration())));
            if (c.from() != null) ps.add(cb.greaterThanOrEqualTo(root.get("occurredAt"), LocalDateTime.ofInstant(c.from(), ZoneOffset.UTC)));
            if (c.to() != null) ps.add(cb.lessThan(root.get("occurredAt"), LocalDateTime.ofInstant(c.to(), ZoneOffset.UTC)));
            if (c.severity() != null) ps.add(cb.equal(root.get("severity"), c.severity()));
            if (c.types() != null && !c.types().isEmpty()) ps.add(root.get("eventType").in(c.types()));
            if (c.excludeTypes() != null && !c.excludeTypes().isEmpty()) ps.add(cb.not(root.get("eventType").in(c.excludeTypes())));
            if (c.ip() != null) ps.add(cb.equal(root.get("sourceIp"), c.ip()));
            return cb.and(ps.toArray(new Predicate[0]));
        };
    }

    static Specification<SecurityEventEntity> spec(Filter f) {
        return (root, query, cb) -> {
            List<Predicate> ps = new ArrayList<>();
            ps.add(cb.greaterThanOrEqualTo(root.get("occurredAt"), LocalDateTime.now(ZoneOffset.UTC).minus(f.range().duration())));
            if (f.type() != null) ps.add(cb.equal(root.get("eventType"), f.type()));
            else if (f.category() != null) ps.add(root.get("eventType").in(f.category().types()));
            if (f.severity() != null) {
                if (HIGH_PLUS.equals(f.severity())) ps.add(root.get("severity").in(Severity.HIGH, Severity.CRITICAL));
                else ps.add(cb.equal(root.get("severity"), Severity.valueOf(f.severity())));
            }
            if (f.outcome() != null) ps.add(cb.equal(root.get("outcome"), f.outcome()));
            if (f.ip() != null) ps.add(cb.equal(root.get("sourceIp"), f.ip()));
            if (f.memberId() != null) ps.add(cb.equal(root.get("memberId"), f.memberId()));
            return cb.and(ps.toArray(new Predicate[0]));
        };
    }
}
