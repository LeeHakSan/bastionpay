#!/bin/bash
# MySQL 데이터 볼륨을 처음 만들 때 앱 계정과 마이그레이션 계정을 생성한다.
# 비밀번호는 docker/.env에서 주입하며, 이 파일에는 실제 값을 넣지 않는다.
set -euo pipefail

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS 'bastionpay_app'@'%' IDENTIFIED BY '${DB_PASSWORD}';
ALTER USER 'bastionpay_app'@'%' IDENTIFIED BY '${DB_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE ON bastionpay_db.* TO 'bastionpay_app'@'%';

CREATE USER IF NOT EXISTS 'bastionpay_migrator'@'%' IDENTIFIED BY '${DB_MIGRATION_PASSWORD}';
ALTER USER 'bastionpay_migrator'@'%' IDENTIFIED BY '${DB_MIGRATION_PASSWORD}';
GRANT ALL PRIVILEGES ON bastionpay_db.* TO 'bastionpay_migrator'@'%';
FLUSH PRIVILEGES;
SQL
