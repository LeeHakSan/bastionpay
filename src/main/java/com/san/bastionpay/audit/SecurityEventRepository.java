package com.san.bastionpay.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEventEntity, Long>, JpaSpecificationExecutor<SecurityEventEntity> {

    interface TypeCount {
        SecurityEventType getType();

        long getCnt();
    }

    interface ItemCount {
        String getItem();

        long getCnt();

        LocalDateTime getLast();
    }

    interface MemberCount {
        Long getItem();

        long getCnt();

        LocalDateTime getLast();
    }

    /** 시간 구간별·종류별·심각도별 건수. bucket 은 (UTC 초 + offset) / sec 의 몫이라, offset 에 +9시간을 주면 한국 시간 경계로 나뉜다. */
    interface BucketCount {
        Number getBucket();

        String getType();

        String getSeverity();

        long getCnt();
    }

    @Query(value = "select floor((timestampdiff(second, '1970-01-01 00:00:00', occurred_at) + :offset) / :sec) as bucket, "
            + "event_type as type, severity as severity, count(*) as cnt from security_event where occurred_at >= :since "
            + "group by bucket, event_type, severity", nativeQuery = true)
    List<BucketCount> countByBucket(@Param("since") LocalDateTime since, @Param("sec") long sec, @Param("offset") long offset);

    /** 기간 안의 이벤트 종류별 건수(많은 순). */
    @Query("select e.eventType as type, count(e) as cnt from SecurityEventEntity e "
            + "where e.occurredAt >= :since group by e.eventType order by count(e) desc")
    List<TypeCount> countByType(@Param("since") LocalDateTime since);

    long countBySeverityInAndOccurredAtGreaterThanEqual(Collection<Severity> severities, LocalDateTime since);

    /** 로그인 실패가 많은 출발지 IP. */
    @Query("select e.sourceIp as item, count(e) as cnt, max(e.occurredAt) as last from SecurityEventEntity e "
            + "where e.eventType = :type and e.occurredAt >= :since and e.sourceIp is not null "
            + "group by e.sourceIp order by count(e) desc, e.sourceIp")
    List<ItemCount> topSourceIps(@Param("type") SecurityEventType type, @Param("since") LocalDateTime since, Pageable page);

    /** 로그인 실패가 많은 계정 식별값(HMAC). */
    @Query("select e.loginSubjectHash as item, count(e) as cnt, max(e.occurredAt) as last from SecurityEventEntity e "
            + "where e.eventType = :type and e.occurredAt >= :since and e.loginSubjectHash is not null "
            + "group by e.loginSubjectHash order by count(e) desc, e.loginSubjectHash")
    List<ItemCount> topSubjects(@Param("type") SecurityEventType type, @Param("since") LocalDateTime since, Pageable page);

    /** 한 출발지 IP 의 이벤트(최근 것부터). 인시던트 티켓 요약에 쓴다. */
    List<SecurityEventEntity> findBySourceIpAndOccurredAtGreaterThanEqualOrderByIdDesc(String sourceIp, LocalDateTime since, Pageable page);

    /** 회원별 이벤트 횟수(같은 종류). 집계 화면에서 쓴다. */
    @Query("select e.memberId as item, count(e) as cnt, max(e.occurredAt) as last from SecurityEventEntity e "
            + "where e.eventType = :type and e.occurredAt >= :since and e.memberId is not null "
            + "group by e.memberId order by count(e) desc, e.memberId")
    List<MemberCount> topMembers(@Param("type") SecurityEventType type, @Param("since") LocalDateTime since, Pageable page);

    /** 기간 안에서 높음 이상(HIGH·CRITICAL)인 이벤트의 종류별 건수. */
    @Query("select e.eventType as type, count(e) as cnt from SecurityEventEntity e "
            + "where e.occurredAt >= :since and e.severity in :severities group by e.eventType")
    List<TypeCount> countBySeverityGroupedByType(@Param("since") LocalDateTime since, @Param("severities") Collection<Severity> severities);

    Page<SecurityEventEntity> findByOccurredAtGreaterThanEqual(LocalDateTime since, Pageable page);

    Page<SecurityEventEntity> findByEventTypeAndOccurredAtGreaterThanEqual(SecurityEventType type, LocalDateTime since, Pageable page);
}
