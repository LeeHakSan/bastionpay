# 보안 이벤트 · 계정 잠금 · 보안 대시보드

Graylog·Wazuh·n8n 연동에 쓰는 BastionPay 쪽 구현 명세다. 실제로 구현된 것만 적는다.

## 1. 보안 이벤트 로그 (JSONL)

- 파일: `logs/security-events.jsonl` (`SECURITY_EVENT_LOG_FILE` 로 변경). 한 줄에 JSON 하나, 일 단위·50MB 단위로 gzip 롤링(30일, 최대 1GB).
- 같은 이벤트를 DB 테이블 `security_event` 에도 저장한다(대시보드 집계용). DB 저장 실패는 요청을 막지 않는다.
- dev 프로파일에서는 콘솔에도 같은 줄이 나온다.
- 일반 앱 로그의 모든 줄에는 `[trace_id]` 가 붙는다(`%5p [traceId] pid ...`). 보안 이벤트의 `trace_id` 와 같은 값이다.
- 응답 헤더 `X-Trace-Id` 로도 같은 값이 나간다. 서버가 만들며 클라이언트가 보낸 값은 쓰지 않는다.

### 필드 (해당되는 것만 나온다. 없는 값은 키 자체가 없다)

| 필드 | 설명 |
|---|---|
| `event_id` | 이벤트 고유 ID(UUID) |
| `event_type` | 이벤트 종류(아래 표) |
| `occurred_at` | 발생 시각, UTC, ISO-8601 (`2026-10-21T07:53:47.410356Z`) |
| `trace_id` | 요청 추적 ID |
| `source_ip` | 요청 출발지 IP |
| `member_id` | 앱 내부 사용자 ID |
| `login_subject_hash` | 로그인에 쓴 이메일의 HMAC-SHA256(소문자·공백 제거 후, 서버 키). 이메일 원문은 남기지 않는다 |
| `account_ref` | 가상 계좌 식별자. 핀테크이용번호 뒤 6자리만 (`fin-***000102`) |
| `transfer_id` | 이체 ID |
| `amount`, `currency` | 금액(원, 정수)과 통화(`KRW`) |
| `severity` | `INFO` `LOW` `MEDIUM` `HIGH` `CRITICAL` |
| `outcome` | `SUCCESS` `FAILURE`(시도 실패) `DENIED`(정책·권한 거부) `REVIEW`(사람 확인 필요) |
| `reason_code` | 판정 이유 코드 |
| `http_method`, `request_path` | 막힌 요청(`AUTHENTICATION_REQUIRED` `ACCESS_DENIED` `CSRF_REJECTED`)에만. 쿼리 스트링 없음, 10자리 이상 숫자는 `***` |

예:
```json
{"event_id":"d15de4f7-...","event_type":"LOGIN_FAILURE","occurred_at":"2026-10-21T07:53:47.410356Z","trace_id":"3d820258b87e","source_ip":"203.0.113.9","login_subject_hash":"1fea7dd5...","severity":"LOW","outcome":"FAILURE","reason_code":"BAD_CREDENTIALS"}
```

### 이벤트 종류

| event_type | 기본 severity | outcome | reason_code |
|---|---|---|---|
| `LOGIN_SUCCESS` | INFO | SUCCESS | |
| `LOGIN_FAILURE` | LOW | FAILURE / DENIED | `BAD_CREDENTIALS` `INVALID_INPUT` / `ACCOUNT_LOCKED` `ACCOUNT_INACTIVE`(DENIED) |
| `AUTHENTICATION_REQUIRED` | LOW | DENIED | `NOT_AUTHENTICATED` |
| `ACCESS_DENIED` | MEDIUM | DENIED | `INSUFFICIENT_AUTHORITY` |
| `CSRF_REJECTED` | MEDIUM | DENIED | `CSRF_TOKEN_INVALID` |
| `TRANSFER_REQUESTED` | INFO | SUCCESS | |
| `TRANSFER_COMPLETED` | INFO | SUCCESS | |
| `TRANSFER_FAILED` | LOW | FAILURE | 은행 응답 코드(앱 오류 코드) |
| `TRANSFER_NEEDS_REVIEW` | HIGH | REVIEW | `WITHDRAW_UNKNOWN` `DEPOSIT_UNKNOWN` `ORG_TOKEN_FAILED` |
| `TRANSFER_REFUNDED` | MEDIUM | FAILURE | 입금 거절 코드 |
| `TRANSFER_REFUND_FAILED` | CRITICAL | REVIEW | 환불 거절 코드 |
| `TRANSFER_REPLAY` | LOW | DENIED | `DUPLICATE_REQUEST` |
| `REFRESH_TOKEN_REUSE` | HIGH | DENIED | `REUSE_DETECTED` |
| `SIGNUP_COMPLETE` `OPENBANKING_LINKED` `OPENBANKING_UNLINKED` | INFO | SUCCESS | |
| `OPENBANKING_LINK_REJECTED` | MEDIUM | FAILURE | 이미 다른 회원에 연결된 은행 고객을 연결하려 함. reason_code `ALREADY_LINKED` |
| `SESSION_EXPIRED` | INFO | DENIED | `IDLE_TIMEOUT` |
| `ACCOUNT_LOCKED` | HIGH | DENIED | `FAILED_LOGIN_THRESHOLD` |
| `ACCOUNT_UNLOCKED` | INFO | SUCCESS | `LOCK_EXPIRED` `ADMIN_UNLOCK` |

표의 앞 12개(`LOGIN_SUCCESS` ~ `TRANSFER_REPLAY`)가 연동 문서의 고정 목록이고, 나머지는 앱이 원래 기록하던 이벤트와 잠금 이벤트다.

### 기록하지 않는 것
비밀번호, 세션 쿠키, 인증 토큰, 이메일 원문, 전체 계좌번호, webhook 주소·비밀값. 은행 응답의 상세 메시지도 남기지 않고 코드(`reason_code`)만 남긴다.

### 출발지 IP
기본은 소켓의 실제 주소(`getRemoteAddr`)다. 요청이 `TRUSTED_PROXIES`(쉼표 구분 IP, 정확히 일치)에서 온 경우에만 `X-Forwarded-For` 를 읽는다. 오른쪽부터 신뢰 프록시를 건너뛰고 처음 나오는 주소를 쓰며, 왼쪽에 끼워 넣은 값과 IP 형식이 아닌 값은 버린다.

## 2. 로그인 실패 집계

- `LOGIN_FAILURE` 에 `source_ip` 와 `login_subject_hash` 가 들어 있다. 같은 계정은 항상 같은 해시다(`LOGIN_SUCCESS` 와도 같다). 없는 계정도 같은 방식으로 해시가 나와서 존재 여부가 드러나지 않는다.
- 키: `SECURITY_LOG_HMAC_KEY`(기본은 `JWT_SECRET` 에서 파생).
- Graylog 집계 예: `event_type:LOGIN_FAILURE` 를 `source_ip` 또는 `login_subject_hash` 로 그룹핑.

## 3. 계정 자동 잠금

- 합성 테스트 계정에만 적용한다. 기본 allowlist: `test@test.com`, `vip@test.com`, `vvip@test.com`. 관리자와 실제 가입 계정은 잠기지 않는다.
- 설정 (`application.yaml` 의 `app.security.lockout`):

| 키 | 기본값 | 의미 |
|---|---|---|
| `enabled` | true | false 면 세지도 잠그지도 않는다 |
| `max-failures` | 5 | 시간창 안의 실패 횟수 |
| `window` | 10m | 실패를 세는 시간창 |
| `lock-duration` | 15m | 잠금 시간 |
| `allowlist` | 위 3개 (`LOCKOUT_ALLOWLIST`) | 잠금 대상 이메일 |

- 잠겨 있는 동안은 비밀번호가 맞아도 거부(`LOGIN_FAILURE`, `DENIED`, `ACCOUNT_LOCKED`)한다. 화면에는 항상 같은 실패 문구를 보여 준다(사유를 알려 주지 않는다).
- 잠금 시간이 지나면 다음 로그인 시도 때 자동 해제하고 `ACCOUNT_UNLOCKED`(`LOCK_EXPIRED`)를 남긴다.
- 잠금·해제는 `security_event` 와 `audit_log` 에 같은 `event_id` 로 남는다. `audit_log`: `occurred_at(UTC)`, `actor_type`(`SYSTEM`/`ADMIN`), `actor_member_id`, `action`, `target_member_id`, `reason_code`, `source_ip`, `trace_id`, `event_id`.
- **외부에서 호출하는 잠금 API 는 아직 구현하지 않았다.** n8n 이 계정을 잠그는 API 는 서버 간 인증 방식을 정한 뒤 만든다. 잠금 성공으로 응답하거나 표시하는 코드는 없다.

## 3-1. 로그인 유지 시간 (활동 없음 자동 로그아웃)

- 마지막 활동 후 30분(`app.session.idle-timeout`) 동안 아무 요청이 없으면 세션이 끝나고 다시 로그인해야 한다. 인증이 필요한 화면 요청이 올 때마다 만료 시각이 30분 뒤로 밀린다(정적 파일과 `GET /session/status` 는 활동이 아니다).
- 세션은 `login_session` 테이블에 UTC 로 기록한다. `end_reason`: `LOGOUT` `IDLE_TIMEOUT` `REVOKED`. Access Token 의 `sid` 클레임이 세션 id(= Refresh Token family id)이고, 세션이 끝나면 토큰의 남은 유효 시간과 상관없이 쓸 수 없다. 로그아웃도 즉시 효력이 있다.
- 만료되면 `SESSION_EXPIRED`(`IDLE_TIMEOUT`) 이벤트가 한 번 남고 로그인 화면에 이유가 나온다(`/login?expired`).
- `app.jwt.refresh-token-ttl`(8시간)은 활동과 상관없는 로그인 최대 유지 시간이다. 활동해도 늘어나지 않는다.
- 헤더의 "자동 로그아웃 mm:ss" 타이머와 "연장" 버튼: 서버가 알려 준 남은 시간부터 센다. 30초마다 서버에 남은 시간을 묻고(연장 아님) 다른 탭의 활동을 반영한다. 5분 이하에서 강조, 1분 이하에서 더 강조하고, 0 이 되면 서버에 한 번 더 확인한 뒤 로그인 화면으로 간다.
- `GET /session/status` → `{"remainingSeconds": n}` (활동 아님), `POST /session/extend`(CSRF 필요) → 남은 시간을 30분으로 되돌리고 같은 형식으로 응답. 로그인하지 않았으면 둘 다 401.

## 4. 보안 대시보드 (관리자 전용)

탭 7개로 나뉜다. 개요는 훑어보는 요약이고, 목록은 각 탭에서 **필터를 걸어 10건씩** 본다. 접근 제어: `/admin/**` 는 `ROLE_ADMIN`(URL 규칙) + 컨트롤러 `@PreAuthorize`. 미인증은 401/로그인 이동, 일반 회원은 403(`ACCESS_DENIED` 기록).

| 탭 | 주소 | 필터 | 쪽 나누기 |
|---|---|---|---|
| 개요 | `GET /admin/security?range=1h\|24h\|7d&rp=` | 기간 | 검토 필요 이체 10건씩 |
| 이벤트 | `GET /admin/security/events` | `range` `category` `type` `severity`(전체\|높음 이상\|INFO~CRITICAL) `outcome` `ip` `member` | 10건 |
| 집계 | `GET /admin/security/stats` | `range` `by`(ip\|account\|member) `type` `min`(최소 횟수) | 10개 묶음 |
| 인시던트 티켓 | `GET /admin/security/tickets` | `status` `severity` `ip`(일부 일치) | 10건 |
| 차단 IP | `GET /admin/security/blocked-ips` | `q`(IP·사유·차단한 사람) | 10건 |
| 계정·권한 | `GET /admin/security/accounts` | `q` `role` `status`(전체\|활성\|잠김 전체\|잠김 관리자\|잠김 로그인 실패) `tier` | 10건 |
| 감사 기록 | `GET /admin/security/audit` | `range` `actor`(ADMIN\|API\|SYSTEM) `action` `target`(회원 번호) | 10건 |

- **이벤트 분류**(`SecurityEventType.Category`): 인증·세션 / 접근 제어 / 이체 / 오픈뱅킹 / 계정·권한 / 보안 대응. 모든 이벤트 종류는 정확히 한 분류에 속한다. 종류(`type`)를 고르면 분류보다 종류가 우선한다.
- 개요 맨 위에 그래프 4개가 있다(Chart.js, `static/js/vendor/chart.umd.js` 4.4.7 을 파일로 두고 CDN 은 쓰지 않는다. CSP 때문에 인라인 스크립트 없이 `static/js/admin-charts.js` 가 그린다): ① 이벤트 추이(심각도별 누적 막대) ② 이체 결과 추이(완료·실패·환불·검토 필요) ③ 이벤트 종류별 비율(많은 6개 + 기타) ④ 로그인 실패 상위 IP 8개. 기간 선택(1시간·24시간·7일)에 따라 5분·1시간·하루(한국 시간 경계) 단위로 나눈다. 데이터는 `GET /admin/security/charts?range=` (관리자 전용 JSON, `SecurityChartService`)에서 가져오고, 스크립트가 실패해도 아래 목록과 표는 그대로 보인다.
- 그래프에 마우스를 올리면 그 막대·조각만 진하게 보이고 나머지는 흐려지며 커서가 손가락 모양이 된다(툴팁에 "눌러서 크게 보기" 안내). 그래프를 누르거나 머리줄의 "크게 보기"를 누르면 그래프 전용 상세 화면 `GET /admin/security/graph/{timeline|transfers|types|ips}?range=`로 간다. 상세 화면은 같은 그래프를 크게 보여 주고, 그 아래에 그래프가 센 이벤트를 10건씩 나열한다(`AdminGraphController`, `SecurityEventSearchService.searchBy`).
- 상세 화면에서 막대·조각을 누르면 같은 주소에 조건이 붙어 다시 열리고 목록이 걸러진다: 이벤트 추이·이체 결과는 `from`(시간 구간 시작, UTC epoch 초)·`series`(심각도 또는 COMPLETED·FAILED·REFUNDED·REVIEW), 종류별 비율은 `type`(이벤트 종류 또는 OTHER=상위 6개 외), 로그인 실패 IP는 `ip`. 고른 조건은 "선택한 조건"으로 보이고 "선택 해제"로 푼다. 잘못된 값은 오류 없이 무시한다.
- 개요의 "분류별 이벤트"는 분류를 펼치면 종류별 건수가 나오고, 누르면 이벤트 탭이 그 조건으로 열린다. 로그인 실패 상위 IP·계정은 5개만 보이고 "집계 보기"로 전체를 본다.
- 형식이 틀린 IP·회원 번호는 조건을 무시하지 않고 안내와 함께 결과를 비운다(전체가 나와 오해하지 않게). 알 수 없는 분류·종류·심각도는 "전체"로 본다. 쪽 번호가 범위를 벗어나면 마지막 쪽으로 맞춘다.
- 집계는 묶음을 최대 1,000개까지 가져와 메모리에서 10개씩 자른다(그 이상은 기간을 줄여서 본다).
- 관리자 화면에는 이메일이 그대로 보인다(관리자는 조치할 대상을 정확히 알아야 한다). 로그·이벤트에는 이메일 원문이 없고, 로그인 실패 집계의 계정은 허용 목록 계정만 이메일로, 나머지는 식별값 앞부분으로 보인다. 서버 간 API 응답은 이메일을 가린다. 시각은 한국 시간이다.
- `POST /admin/security/accounts/{memberId}/unlock` — 개요에서 잠금 해제. 관리자 + CSRF 토큰 필요, 감사 기록에 해제한 관리자가 남는다.

## 4-1. 보안 대응 기능 (티켓 · IP 차단 · 계정 잠금 · 권한 회수)

> 구조만 만들어 둔 상태다. Graylog·Wazuh·n8n 과의 실제 연동은 아직 없고, 이 앱은 바깥으로 호출하지 않는다. 나중에 자동화가 같은 기능을 부를 수 있도록 입구(API)를 열어 두었다.

관리자는 보안 대시보드의 탭(개요 · 인시던트 티켓 · 차단 IP · 계정·권한)에서 쓰고, 자동화는 `X-API-Key` 로 `/api/admin/**` 를 호출한다. 두 길 모두 같은 서비스를 거치므로 규칙이 똑같다. 조치마다 보안 이벤트와 감사 기록(`audit_log`, 행위자 `ADMIN`/`API`)이 남는다.

### 화면 (관리자 전용, POST 는 CSRF 토큰 필요)
| 주소 | 기능 |
|---|---|
| `GET /admin/security/tickets` | 티켓 목록(상태·심각도 필터), 티켓 만들기 |
| `POST /admin/security/tickets` | 티켓 생성/갱신 (`ip`, `title?`, `severity?`, `hours?`) |
| `POST /admin/security/tickets/close` | 선택한 티켓 종료 (`ids`) |
| `POST /admin/security/tickets/close-all` | 열린 티켓 전체 종료 (`severity?` 를 주면 그 심각도만). 화면에서는 한 번 더 확인한 뒤에만 실행 |
| `GET /admin/security/blocked-ips` | 차단 목록·검색 |
| `POST /admin/security/blocked-ips`, `/unblock` | IP 차단(`ip`, `reason?`)·해제 |
| `GET /admin/security/accounts` | 회원 목록·검색, 허용 목록 밖 관리자 |
| `POST /admin/security/accounts/action` | `action`=`lock`\|`unlock`\|`revoke`, `target`=회원 번호 또는 이메일, `reason?` |

### 서버 간 API (헤더 `X-API-Key: <SECURITY_API_KEY>`)
키가 비어 있으면 모든 요청이 401 이다(닫힘). 키가 틀리면 401 + `API_AUTH_FAILED` 이벤트(시도한 키 값은 남기지 않는다). JSON 필드는 snake_case.

| 메서드·주소 | 본문 / 쿼리 | 응답 |
|---|---|---|
| `POST /api/admin/incident` | `src_ip`, `title?`, `severity?`(LOW\|MEDIUM\|HIGH\|CRITICAL), `hours?`(기본 24, 최대 720) | 201 새 티켓 / 200 갱신 `{created, incident}` |
| `GET /api/admin/incidents` | `status?`(open\|closed), `severity?`, `page`, `per_page`(최대 100) | `{count, incidents[], page, per_page, total, pages}` |
| `POST /api/admin/incident/close` | `id` | 200 / 404(없거나 이미 종료) |
| `POST /api/admin/incidents/close` | `ids[]` 또는 `all_open: true` (+ `severity?`) | `{count}` |
| `POST /api/admin/block` | `ip`, `reason?` | 200 `{blocked, changed}` / 400 |
| `POST /api/admin/unblock` | `ip` | 200 `{changed}` |
| `GET /api/admin/blocked` | `q?`, `page`, `per_page` | 목록 |
| `POST /api/admin/lock` | `member_id` 또는 `email`, `reason?` | 200 `{locked, changed}` / 403(잠글 수 없는 계정) / 404 / 409 |
| `POST /api/admin/unlock` | `member_id` 또는 `email` | 200 `{changed}` / 404 |
| `POST /api/admin/revoke` | `member_id` 또는 `email`, `reason?` | 200 `{revoked, changed}` / 404 / 409(마지막 관리자) |
| `GET /api/admin/users` | `q?`, `role?`, `locked?`(1\|0) | 회원 목록(이메일은 가려서 — 관리자 화면과 달리 서버 간 응답은 이메일을 가린다) |
| `GET /api/admin/violations` | - | 허용 목록 밖 관리자 |

### 티켓 생성 방식
- 키는 **출발지 IP**다. 같은 IP 의 **열린 티켓은 하나뿐**이고(DB 제약), 이미 있으면 새로 만들지 않고 갱신한다.
- 요약은 그 IP 의 보안 이벤트(`security_event`)를 최근 `hours` 시간 모아서 자동으로 만든다: 관련 이벤트 수와 종류별 집계, 최초·최종 시각(KST), 이미 취해진 조치(`IP_BLOCKED` `ACCOUNT_LOCKED` 등), 최고 심각도, 최근 20건 타임라인.
- 심각도는 내려가지 않는다(요청값·모은 이벤트의 최고값·기존 값 중 가장 높은 것). `INFO` 이벤트는 LOW 로 본다.
- 이미 종료한 티켓의 사건은 새 티켓이 다시 모으지 않는다(마지막 종료 시각 이후 사건만).
- 필드: `id, title, src_ip, severity, status(OPEN|CLOSED), summary, event_count, actions, created_by, closed_by, created_at, updated_at, closed_at`(UTC).

### 지키는 규칙
- **IP 차단**: 차단된 IP 의 요청은 앱에 닿기 전에 403 이다(`IP_BLOCKED_REQUEST` 이벤트는 같은 IP 당 1분에 한 번). 지금 접속한 관리자의 IP 는 차단할 수 없다. 유효한 API 키를 가진 요청은 차단의 영향을 받지 않는다. IPv6 는 짧은 표기로 통일한다. 이미 차단된 IP 는 처음 사유·시각을 덮어쓰지 않는다.
- **계정 잠금**: 자동 잠금 대상(합성 테스트 계정, `LOCKOUT_ALLOWLIST`)만 잠글 수 있고, 관리자 계정과 자기 자신은 안 된다. 잠그면 그 계정의 세션·토큰을 즉시 끊는다. 잠금을 풀면 수동 잠금과 로그인 실패 잠금을 모두 푼다. 잠글 수 없는 계정을 잠갔다고 응답하는 코드는 없다.
- **권한 회수**: 관리자 권한(`ADMIN` → `USER`)만 회수한다. 자기 자신과 마지막 관리자는 회수할 수 없다. 회수하면 세션을 즉시 끊는다. 관리자 허용 목록(`ADMIN_ALLOWLIST`, 기본 `admin@test.com`) 밖의 관리자는 "과잉권한"으로 표시한다.
- 새 이벤트 종류: `INCIDENT_CREATED` `INCIDENT_CLOSED` `IP_BLOCKED` `IP_UNBLOCKED` `IP_BLOCKED_REQUEST` `ROLE_REVOKED` `API_AUTH_FAILED` (`reason_code`: `ADMIN_*`/`API_*` 접두로 행위자를 구분).

## 4-2. 회원 등급 (자동 승급·강등과 이체 한도)

| 등급 | 1회 이체 한도 | 올라가는 조건(누적 이체 금액) |
|---|---|---|
| `STANDARD` | 2,000,000원 | 가입 시 기본 |
| `VIP` | 10,000,000원 | 누적 10,000,000원 이상 |
| `VVIP` | 제한 없음 | 누적 50,000,000원 이상 |

- **승급(자동)**: 이체가 **완료**될 때마다 누적(완료된 이체의 합)을 계산해, 기준을 넘으면 바로 올린다. 환불·실패·검토 중인 이체는 누적에 들어가지 않는다. 승급해도 누적은 이어서 센다.
- **강등(자동)**: 앱을 3개월 이용하지 않으면 **한 단계씩** 내린다(VVIP→VIP→STANDARD). 마지막 이용(또는 마지막 등급 변경) 후 석 달이 지날 때마다 한 단계이고, 7개월 이용하지 않았다면 두 단계를 한 번에 내린다. STANDARD 아래로는 내려가지 않는다. 강등되면 누적 이체 금액은 그 시각부터 **다시 센다**(내려간 뒤 바로 다시 오르지 않는다).
- **이용으로 보는 것**: 로그인, 그리고 로그인한 화면을 쓰는 활동(하루에 한 번만 기록). 로그인할 때 이전 이용 시각으로 강등 여부를 먼저 보고 그다음 이용 시각을 갱신하며, 매일 새벽 4시 50분 배치가 로그인하지 않은 회원도 확인한다.
- **한도 검사**: 접수 전에 DB 의 등급으로 검사한다(토큰의 등급이 아니다. 승급·강등이 바로 반영된다). 이미 접수한 요청의 재전송(멱등)은 등급이 내려가도 결과를 그대로 돌려준다. 은행(가짜 서버)의 건당 한도는 사실상 없고(API 의 12자리 상한), 한도는 이용기관(BastionPay)이 등급으로 정한다.
- 등급이 바뀌면 `TIER_CHANGED` 이벤트(`PROMOTED_BY_VOLUME` / `DEMOTED_INACTIVE`)와 감사 기록(행위자 `SYSTEM`)이 남는다.
- 설정(`app.tier`): `vip-threshold` `vvip-threshold` `standard-limit` `vip-limit` `inactivity-months`. 승급 기준 금액은 기본값이며 정책에 맞게 바꾼다.
- 컬럼(`member`): `last_active_at`, `tier_changed_at`, `tier_baseline_at`(누적을 세기 시작하는 시각). 시각은 서버 지역 시간이다.

## 5. 아직 하지 않은 것
- Graylog·Wazuh·n8n 과의 실제 연동(수신 설정, 알림·웹훅 호출 등). 입구(API)와 티켓 생성 방식만 만들어 둠
- 누적 이체 한도
- 이벤트 보관 기간 정리(DB). 현재 `security_event` 는 계속 쌓인다.
