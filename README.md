# # BloxHunter v5

Roblox 관련 자동화 및 데이터 조회 스크립트인 **BloxHunter v5** 리포지토리입니다. 

## 🚀 시작하기 전에 (Prerequisites)

이 프로그램을 실행하려면 컴퓨터에 **Python 3.x** 버전이 설치되어 있어야 합니다.
* [Python 공식 홈페이지](https://python.org)에서 다운로드 시 반드시 **"Add Python to PATH"** 옵션을 체크해 주세요.

## 📦 설치 및 실행 방법 (Installation & Usage)

### 1. 리포지토리 다운로드
이 저장소를 클론하거나 ZIP 파일로 다운로드한 후 압축을 풀어줍니다.
```bash
git clone https://github.com
cd -
```

### 2. 필수 라이브러리 설치
프로그램 실행에 필요한 패키지를 설치합니다. (스크립트 내부 구조에 따라 추가 라이브러리가 필요할 수 있습니다.)
```bash
pip install requests
```

### 3. 환경 설정 (중요)
실행하기 전, 폴더 내에 있는 `config.json` 파일을 메모장이나 코드 에디터로 열어 **필요한 설정값(API 키, 계정 정보 등)**을 올바르게 입력하고 저장해 주세요.

### 4. 프로그램 실행
모든 설정이 완료되었다면 최신 버전인 `bloxhunter_v5_final.py` 파일을 실행합니다.
```bash
python bloxhunter_v5_final.py
```

## 📂 파일 구성 (Repository Structure)

* `bloxhunter_v5_final.py`: 최신 기능이 반영된 메인 실행 스크립트
* `bloxhunter_v5.py`: 이전 버전의 기본 스크립트
* `config.json`: 사용자 정의 및 API 연동을 위한 설정 파일
* `words_builtin.txt`: 프로그램 내부에서 참조하는 내장 단어/데이터 텍스트 파일
