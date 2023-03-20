# Lambda를 사용한 GuardDuty Threat IP 차단 프로세스

### Velog
- [Lambda를-사용한-GuardDuty-Threat-IP-차단-프로세스-구현하기](https://velog.io/@yieon/Lambda%EB%A5%BC-%EC%82%AC%EC%9A%A9%ED%95%9C-GuardDuty-Threat-IP-%EC%B0%A8%EB%8B%A8-%ED%94%84%EB%A1%9C%EC%84%B8%EC%8A%A4-%EA%B5%AC%ED%98%84%ED%95%98%EA%B8%B0)

## GuardDuty란?
```
Amazon GuardDuty는 AWS 계정 및 워크로드에서 악의적 활동을 모니터링하고 상세한 보안 결과를 제공하여 가시성 및 해결을 촉진하는 위협 탐지 서비스입니다.
```
- https://aws.amazon.com/ko/guardduty/

1. AWS 계정, 인스턴스, 컨테이너 워크로드, 사용자, 데이터베이스 및 스토리지에서 잠재적 위협 요소를 지속적으로 모니터링할 수 있습니다.
2. 이상 탐지, 기계 학습, 동작 모델링 및 AWS와 선도적인 서드 파티의 위협 인텔리전스 피드를 사용하여 위협을 빠르게 노출할 수 있습니다.
3. 자동 대응을 시작하여 위협을 조기에 완화할 수 있습니다.

## GuardDuty를 통한 DevSevOps 도입
- GuardDuty를 활성화하면 다음과 같이 severity(심각도)에 따른 AWS의 감지된 위협을 확인할 수 있습니다.
- 향상된 보안성을 위해 EKS, EC2, Lambda, S3, RDS등 여러 위협에 대해 감지하고 대응할 수 있어야 합니다.
- 최근 public cloud의 도입이 늘어난 만큼 IDC 환경이 아닌 AWS에서의 기술적 보안 방법을 활용할 수 있어야 합니다.

## GuardDuty 위협 IP 차단 프로세스 구성

#### 이벤트 발생 흐름
-     1. GuardDuty 위협 탐지
    
-     2. 탐지 이벤트 발생
      2-1. 설정한 CloudWatch Event의 규칙에서 이벤트가 발생되어 연결된 Lambda 함수 동작
      2-2. Lambda에서 Event 정보에 따른 NACL Inbound Deny Rule 삽입
      2-3. 차단 후 Rule Number를 설정하여 연결한 DynamoDB의 Table에 항목 추가
      2-4. Slack Message 알림 전송

-     3. RuleNumber의 설정한 최대 개수에 의거한 최대 개수 초과 발생 이벤트 처리 프로세스 동작
      3-1. NetworkACLId기준 10건 초과의 Threat IP 처리 된 이력이 있으면 오래된 이력부터 삭제하여 RuleNumber Range를 유지 (최대 20건 이내)