# BastionPay 설치·실행 가이드

이 문서는 새 Windows PC 또는 VM에서 웹 앱과 교육용 MockBank를 재현하는 최소 경로를 정리합니다. pfSense·Graylog·Wazuh·n8n은 별도 VM/컨테이너와 운영 데이터가 필요한 실습 구성이라, 저장소에는 재현에 필요한 설정 파일과 검증 기록을 함께 보관하되 단일 명령으로 자동 설치하지 않습니다.

## 0. 사전 준비

- Git
- JDK 21
- Docker Desktop 및 Docker Compose v2
- 사용하지 않는 로컬 포트: 3306, 3307, 8080, 8090

아래 명령은 Windows PowerShell 기준입니다. Linux/macOS에서는 `gradlew.bat` 대신 `./gradlew`를 사용합니다.

## 1. 저장소 받기

```powershell
git clone https://github.com/LeeHakSan/bastionpay.git
cd bastionpay
```

## 2. BastionPay MySQL(3306) 기동

루트 앱용 MySQL은 앱용 DML 계정과 Flyway용 DDL 계정을 초기화 스크립트로 분리합니다. 처음 생성된 Docker 볼륨에서만 `docker/init/01-users.sh`가 실행됩니다.

```powershell
Copy-Item docker/.env.example docker/.env
docker compose --env-file docker/.env -f docker/docker-compose.yml up -d
```

`docker/.env`의 `DB_PASSWORD`, `DB_MIGRATION_PASSWORD`는 루트 `.env`의 같은 이름 값과 일치해야 합니다.

## 3. MockBank MySQL(3307) 기동

```powershell
Set-Location mockbank-mysql
Copy-Item .env.example .env
docker compose --env-file .env -f docker-compose.yml up -d
Set-Location ..
```

앱 계정·마이그레이션 계정 비밀번호는 `mockbank-mysql/.env`와 `mock-openbanking/.env`에서 동일하게 맞춥니다.

## 4. MockBank 실행

```powershell
Copy-Item mock-openbanking/.env.example mock-openbanking/.env
Set-Location mock-openbanking
.\gradlew.bat bootRun
```

MockBank는 기본적으로 `http://localhost:8090`에서 대기합니다. DB 스키마 생성 후 테스트 데이터가 필요하면 [`db/seed/README.md`](../db/seed/README.md)의 `mockbank.sql` 또는 `mockbank-test.sql` 절차를 따릅니다.

## 5. BastionPay 환경변수와 실행

새 PowerShell 창에서 프로젝트 루트로 돌아와 실행합니다.

```powershell
Set-Location ..
Copy-Item .env.example .env
```

`.env`에는 최소한 다음 값을 환경에 맞게 입력합니다.

```dotenv
DB_USERNAME=bastionpay_app
DB_PASSWORD=<docker/.env와 동일한 앱 비밀번호>
DB_MIGRATION_USERNAME=bastionpay_migrator
DB_MIGRATION_PASSWORD=<docker/.env와 동일한 마이그레이션 비밀번호>
JWT_SECRET=<32바이트 이상 무작위 값>
OPENBANKING_BASE_URL=http://localhost:8090
```

가장 빠른 페이지·API 확인은 개발 HTTPS를 끄고 실행합니다.

```dotenv
DEV_HTTPS=false
SERVER_ADDRESS=127.0.0.1
SERVER_PORT=8080
```

```powershell
.\gradlew.bat bootRun
```

앱은 기본적으로 `http://localhost:8080`에서 대기합니다. 오픈뱅킹 OAuth 전체 흐름을 실행하려면 `config/local-dev.p12`를 로컬에서 생성하고, MockBank에 등록된 redirect URI와 `OPENBANKING_REDIRECT_URI`를 같은 값으로 맞춰야 합니다. 인증서와 개인 키 파일은 보안상 저장소에 올리지 않습니다.

## 6. 테스트와 더미 데이터

```powershell
.\gradlew.bat test
Set-Location mock-openbanking
.\gradlew.bat test
```

더미 계정·거래·보안 이벤트를 넣는 방법과 시나리오별 데이터는 [`db/seed/README.md`](../db/seed/README.md)에 있습니다. SQL 파일의 계정·client secret·전화번호는 교육용 더미 값이며 실제 서비스에서 사용하면 안 됩니다.

## 7. 관제 구성 파일과 기본 포트

| 구성 | 저장소 위치 | 기록된 기본 접점 |
|---|---|---|
| Graylog | [`_graylog/`](../_graylog/) | Web UI 9000, Beats 5044, GELF UDP 12201 |
| Wazuh | [`_wazuh/`](../_wazuh/) | Agent/Manager 1514–1515, 설정에 기록된 n8n Webhook |
| n8n | [`_n8n/`](../_n8n/) | 5678, Graylog/Wazuh Webhook 두 개 |
| pfSense | [README 망 구성](../README.md#6-b-pfsense-망-구성) | 관리 GUI 10.10.10.1, OpenVPN TAP UDP 1194–1196. 키가 포함된 XML 백업은 배포하지 않음 |
| Filebeat | [`ops/filebeat.yml`](../ops/filebeat.yml) | Graylog Beats 192.168.3.16:5044 |

IP 주소와 수집 대상은 실습망의 현재 배치에 종속됩니다. 새 환경에서는 설정 파일의 주소·인증서·웹훅 키를 반드시 로컬 값으로 교체하고, 공개 저장소에는 실제 키를 커밋하지 않습니다.

과거에 공개된 pfSense 백업에는 OpenVPN 정적 키, CA 및 서버·클라이언트 개인 키, 관리자 비밀번호 해시가 포함되어 있었습니다. 파일을 현재 트리에서 제거해도 Git 기록의 이전 커밋에는 남습니다. 해당 키·인증서·관리자 비밀번호는 실습 장비에서 폐기하고 재발급·변경해야 합니다. 새 백업은 비공개로 보관하세요.

## 8. 재현 범위와 미완료 항목

- 웹·MockBank 단독 실행과 Spring 테스트는 저장소 기준으로 재현할 수 있습니다.
- pfSense VM, OpenVPN TAP, Graylog/Wazuh/n8n 연계는 동일한 VM·망 토폴로지와 별도 인증정보가 필요합니다.
- README의 [남은 일과 확인하지 못한 것](../README.md#10-남은-일과-확인하지-못한-것)에 적힌 SOC 이전, 원격 syslog, MockBank DB 외부 접속, 최소권한 규칙 등은 현재 완료로 표시하지 않습니다.
