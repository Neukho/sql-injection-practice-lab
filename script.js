const MAX_INPUT_LENGTH = 96;

const USERS = [
  { username: "admin", password: "rainbow", role: "Administrator", state: "full access" },
  { username: "analyst", password: "logs2026", role: "Security Analyst", state: "report view" },
  { username: "student", password: "practice", role: "Student", state: "lab access" }
];

const ASSETS = [
  { id: 1, name: "training-lab", category: "lab", owner: "security" },
  { id: 2, name: "exam-sheet", category: "internal", owner: "faculty" },
  { id: 3, name: "owasp-guide", category: "guide", owner: "security" },
  { id: 4, name: "flag-list", category: "secret", owner: "redteam" }
];

const LEAKED_ROWS = [
  { id: "U-01", name: "admin / [mock-redacted]", category: "users", owner: "simulated exposure" },
  { id: "U-02", name: "analyst / [mock-redacted]", category: "users", owner: "simulated exposure" }
];

const scenarios = {
  login: {
    label: "로그인 우회",
    short: "Authentication Bypass",
    description: "문자열 결합으로 만든 로그인 쿼리가 인증 우회에 어떻게 무너지는지 본다.",
    developerTitle: "로그인 코드 리뷰 포인트",
    learnerTitle: "로그인 실습 관찰 포인트",
    initial: {
      username: "student",
      password: "practice"
    },
    fields: [
      { name: "username", label: "Username", type: "text", placeholder: "student" },
      { name: "password", label: "Password", type: "text", placeholder: "practice" }
    ],
    samples: [
      {
        label: "정상 로그인",
        note: "기본 흐름 확인",
        values: { username: "student", password: "practice" }
      },
      {
        label: "주석 우회",
        note: "비밀번호 검증 절 끊기",
        values: { username: "admin' --", password: "anything" }
      },
      {
        label: "항상 참",
        note: "WHERE 절 전체 우회",
        values: { username: "' OR '1'='1", password: "' OR '1'='1" }
      },
      {
        label: "파괴 시도",
        note: "stacked query 위험",
        values: { username: "admin'; DROP TABLE users; --", password: "x" }
      }
    ],
    getUnsafeQuery(values) {
      return `SELECT * FROM users\nWHERE username = '${values.username}'\nAND password = '${values.password}';`;
    },
    getSafeQuery(values) {
      return `SELECT * FROM users\nWHERE username = ?\nAND password = ?;\n-- params: ["${values.username}", "${values.password}"]`;
    },
    evaluate(values, mode) {
      const username = values.username.trim();
      const password = values.password.trim();
      const patterns = detectPatterns(`${username} ${password}`);
      const directMatch = USERS.find((user) => user.username === username && user.password === password);
      const steps = [
        "원인: 입력값이 로그인 쿼리의 username/password 위치에 들어간다고 가정한다."
      ];

      if (mode === "safe") {
        steps.push("방어: prepared statement에서는 입력값이 SQL 구문이 아니라 단순 파라미터로 전달된다.");
        if (patterns.any) {
          steps.push("결과: 주입 패턴이 포함되어 있어도 쿼리 구조는 변경되지 않는다.");
        }

        if (directMatch) {
          return {
            title: "정상 로그인 성공",
            summary: "정확한 계정 정보가 입력되어 인증이 정상 처리되었다.",
            steps,
            rows: [formatLoginRow(directMatch, "legitimate login")]
          };
        }

        return {
          title: "주입 문자열이 단순 값으로 처리됨",
          summary: "safe mode에서는 SQL 구문이 바뀌지 않으므로 인증 우회가 발생하지 않는다.",
          steps,
          rows: []
        };
      }

      steps.push("변화: vulnerable mode에서는 입력값이 그대로 WHERE 절에 이어 붙는다.");

      if (directMatch) {
        steps.push("결과: 정상 계정과 비밀번호가 일치해 합법적으로 로그인된다.");
        return {
          title: "정상 로그인 성공",
          summary: "취약한 코드라도 올바른 계정 정보에서는 일반 로그인처럼 동작한다.",
          steps,
          rows: [formatLoginRow(directMatch, "legitimate login")]
        };
      }

      if (username.toLowerCase().includes("admin' --")) {
        steps.push("변화: 주석 기호가 뒤의 비밀번호 조건을 잘라냈다.");
        steps.push("결과: username = 'admin' 조건만 남아 관리자 계정이 선택된다.");
        return {
          title: "관리자 계정 우회 로그인",
          summary: "comment termination으로 비밀번호 검증이 무력화되었다.",
          steps,
          rows: [formatLoginRow(USERS[0], "comment-based bypass")]
        };
      }

      if (patterns.tautology) {
        steps.push("변화: 항상 참이 되는 조건이 들어와 WHERE 절 전체가 참으로 평가된다.");
        steps.push("결과: 실습에서는 첫 번째 반환 행을 선택해 인증 우회를 시뮬레이션한다.");
        return {
          title: "조건 우회로 인증 성공",
          summary: "tautology payload 때문에 필터가 무력화되었다.",
          steps,
          rows: [formatLoginRow(USERS[0], "tautology bypass")]
        };
      }

      if (patterns.stacked) {
        steps.push("변화: 세미콜론 뒤에 추가 구문이 감지되어 stacked query 위험이 확인되었다.");
        steps.push("결과: 실습 사이트에서는 실제 삭제를 수행하지 않고 위험만 경고한다.");
        return {
          title: "추가 명령 실행 위험 감지",
          summary: "파괴적 명령이 이어질 수 있는 형태의 입력이 감지되었다.",
          steps,
          rows: []
        };
      }

      if (patterns.union) {
        steps.push("변화: UNION 기반 탐색 흔적이 감지되었다.");
        steps.push("결과: 로그인 쿼리에서는 주로 오류 기반 정보 노출이나 구조 탐색 단계로 이어질 수 있다.");
        return {
          title: "오류 기반 정보 노출 가능성",
          summary: "인증 우회 대신 쿼리 구조 탐색 단계로 이어질 수 있다.",
          steps,
          rows: []
        };
      }

      steps.push("결과: 일치하는 계정이 없어 인증에 실패했다.");
      return {
        title: "로그인 실패",
        summary: "주입 조건이 없고 자격 증명도 일치하지 않아 결과가 반환되지 않았다.",
        steps,
        rows: []
      };
    }
  },
  search: {
    label: "검색 필터 우회",
    short: "Search Filter Abuse",
    description: "검색창 하나만 있어도 SQL 구문이 섞이면 전체 데이터 노출과 UNION 기반 정보 노출이 생길 수 있다.",
    developerTitle: "검색 기능 코드 리뷰 포인트",
    learnerTitle: "검색 실습 관찰 포인트",
    initial: {
      keyword: "guide"
    },
    fields: [
      { name: "keyword", label: "Search Keyword", type: "text", placeholder: "guide" }
    ],
    samples: [
      {
        label: "정상 검색",
        note: "기본 검색 결과",
        values: { keyword: "guide" }
      },
      {
        label: "전체 노출",
        note: "필터 우회",
        values: { keyword: "%' OR 1=1 --" }
      },
      {
        label: "UNION 노출",
        note: "다른 테이블 결합",
        values: { keyword: "%' UNION SELECT username, role, state, id FROM users --" }
      },
      {
        label: "삭제 시도",
        note: "파괴적 명령 연결",
        values: { keyword: "x'; DELETE FROM assets; --" }
      }
    ],
    getUnsafeQuery(values) {
      return `SELECT id, name, category, owner FROM assets\nWHERE name LIKE '%${values.keyword}%';`;
    },
    getSafeQuery(values) {
      return `SELECT id, name, category, owner FROM assets\nWHERE name LIKE ?;\n-- params: ["%${values.keyword}%"]`;
    },
    evaluate(values, mode) {
      const keyword = values.keyword.trim();
      const patterns = detectPatterns(keyword);
      const filtered = ASSETS.filter((asset) => asset.name.includes(keyword));
      const steps = [
        "원인: 검색 입력이 LIKE 절 내부에 들어간다고 가정한다."
      ];

      if (mode === "safe") {
        steps.push("방어: safe mode에서는 LIKE 절의 와일드카드 문자열도 파라미터로 바인딩된다.");
        if (patterns.any) {
          steps.push("결과: 특수 문자열이 있어도 검색어 자체로만 해석되므로 전체 노출이 일어나지 않는다.");
        }

        return {
          title: filtered.length ? "정상 검색 완료" : "검색 결과 없음",
          summary: filtered.length
            ? "입력한 키워드와 일치하는 mock asset만 반환되었다."
            : "safe mode에서는 SQL 의미가 바뀌지 않아 결과가 늘어나지 않는다.",
          steps,
          rows: filtered
        };
      }

      steps.push("변화: vulnerable mode에서는 검색 문자열이 LIKE 절 내부에 그대로 삽입된다.");

      if (patterns.union) {
        steps.push("변화: UNION SELECT 패턴이 감지되어 다른 테이블 데이터가 결합되는 상황을 시뮬레이션한다.");
        steps.push("결과: 실습에서는 사용자 테이블이 노출된 것처럼 mock row를 추가한다.");
        return {
          title: "다른 테이블 정보가 함께 노출됨",
          summary: "UNION 기반 정보 노출이 발생해 원래 검색 결과 외에 계정 정보가 합쳐졌다.",
          steps,
          rows: [...ASSETS.slice(0, 2), ...LEAKED_ROWS]
        };
      }

      if (patterns.tautology) {
        steps.push("변화: 항상 참 조건 때문에 WHERE 필터가 무력화되었다.");
        steps.push("결과: 실습에서는 전체 asset 목록이 노출된 것으로 처리한다.");
        return {
          title: "전체 데이터 노출",
          summary: "검색 필터가 우회되어 모든 mock asset이 반환되었다.",
          steps,
          rows: ASSETS
        };
      }

      if (patterns.stacked) {
        steps.push("변화: 검색 쿼리 뒤에 추가 명령이 붙어 데이터 삭제 위험이 생길 수 있다.");
        steps.push("결과: 실습에서는 실제 삭제를 수행하지 않고 위험도만 설명한다.");
        return {
          title: "추가 명령 실행 위험 감지",
          summary: "stacked query 형태의 입력이 감지되었다. 운영 환경이라면 데이터 손상으로 이어질 수 있다.",
          steps,
          rows: []
        };
      }

      return {
        title: filtered.length ? "정상 검색 완료" : "검색 결과 없음",
        summary: filtered.length
          ? "주입 없이 일반 검색처럼 동작했다."
          : "입력한 키워드와 일치하는 mock asset이 없다.",
        steps,
        rows: filtered
      };
    }
  }
};

const state = {
  mode: "vulnerable",
  scenario: "login",
  values: Object.fromEntries(
    Object.entries(scenarios).map(([key, config]) => [key, normalizeScenarioValues(config.initial)])
  )
};

const modeToggle = document.getElementById("modeToggle");
const scenarioTabs = document.getElementById("scenarioTabs");
const scenarioDescription = document.getElementById("scenarioDescription");
const sampleList = document.getElementById("sampleList");
const formFields = document.getElementById("formFields");
const labForm = document.getElementById("labForm");
const resetButton = document.getElementById("resetButton");
const consoleTitle = document.getElementById("consoleTitle");
const statusBadge = document.getElementById("statusBadge");
const unsafeQuery = document.getElementById("unsafeQuery");
const safeQuery = document.getElementById("safeQuery");
const resultTitle = document.getElementById("resultTitle");
const resultSummary = document.getElementById("resultSummary");
const resultSteps = document.getElementById("resultSteps");
const developerInsightTitle = document.getElementById("developerInsightTitle");
const developerInsightBody = document.getElementById("developerInsightBody");
const learnerInsightTitle = document.getElementById("learnerInsightTitle");
const learnerInsightBody = document.getElementById("learnerInsightBody");
const resultTableHead = document.getElementById("resultTableHead");
const resultTableBody = document.getElementById("resultTableBody");

initialize();

function initialize() {
  renderScenarioTabs();
  renderModeButtons();
  renderScenario();
  setupRevealObserver();
}

function renderScenarioTabs() {
  scenarioTabs.innerHTML = Object.entries(scenarios)
    .map(([key, scenario]) => {
      const active = key === state.scenario ? " active" : "";
      return `<button type="button" class="scenario-tab${active}" data-scenario="${key}" aria-selected="${key === state.scenario}">
        <strong>${scenario.label}</strong>
        <span>${scenario.short}</span>
      </button>`;
    })
    .join("");

  scenarioTabs.querySelectorAll("[data-scenario]").forEach((button) => {
    button.addEventListener("click", () => {
      syncValuesFromInputs();
      state.scenario = button.dataset.scenario;
      renderScenarioTabs();
      renderScenario();
    });
  });
}

function renderModeButtons() {
  modeToggle.querySelectorAll("[data-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      syncValuesFromInputs();
      state.mode = button.dataset.mode;
      updateModeButtons();
      runSimulation();
    });
  });

  updateModeButtons();
}

function updateModeButtons() {
  modeToggle.querySelectorAll("[data-mode]").forEach((button) => {
    const active = button.dataset.mode === state.mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });

  statusBadge.textContent = state.mode === "safe" ? "SAFE MODE" : "VULNERABLE MODE";
  statusBadge.className = `status-badge ${state.mode}`;
}

function renderScenario() {
  const scenario = scenarios[state.scenario];
  consoleTitle.textContent = scenario.label;
  scenarioDescription.textContent = scenario.description;
  renderFields();
  renderSamples();
  runSimulation();
}

function renderFields() {
  const scenario = scenarios[state.scenario];
  const values = state.values[state.scenario];

  formFields.innerHTML = scenario.fields
    .map(
      (field) => `<div class="field">
        <label for="${field.name}">${field.label}</label>
        <input id="${field.name}" name="${field.name}" type="${field.type}" placeholder="${field.placeholder}" value="${escapeHtml(values[field.name] ?? "")}">
      </div>`
    )
    .join("");
}

function renderSamples() {
  const scenario = scenarios[state.scenario];
  sampleList.innerHTML = scenario.samples
    .map(
      (sample, index) => `<button type="button" class="sample-button" data-sample-index="${index}">
        <strong>${sample.label}</strong>
        <span>${sample.note}</span>
      </button>`
    )
    .join("");

  sampleList.querySelectorAll("[data-sample-index]").forEach((button) => {
    button.addEventListener("click", () => {
      const sample = scenario.samples[Number(button.dataset.sampleIndex)];
      state.values[state.scenario] = normalizeScenarioValues(sample.values);
      renderFields();
      runSimulation();
    });
  });
}

labForm.addEventListener("submit", (event) => {
  event.preventDefault();
  syncValuesFromInputs();
  runSimulation();
});

formFields.addEventListener("input", () => {
  syncValuesFromInputs();
  runSimulation();
});

resetButton.addEventListener("click", () => {
  state.values[state.scenario] = normalizeScenarioValues(scenarios[state.scenario].initial);
  renderFields();
  runSimulation();
});

function syncValuesFromInputs() {
  const formData = new FormData(labForm);
  const updatedValues = {};

  formData.forEach((value, key) => {
    updatedValues[key] = normalizeInput(value);
  });

  if (Object.keys(updatedValues).length) {
    state.values[state.scenario] = updatedValues;
  }
}

function runSimulation() {
  const scenario = scenarios[state.scenario];
  const values = state.values[state.scenario];
  const result = scenario.evaluate(values, state.mode);

  unsafeQuery.textContent = scenario.getUnsafeQuery(values);
  safeQuery.textContent = scenario.getSafeQuery(values);
  resultTitle.textContent = result.title;
  resultSummary.textContent = result.summary;
  resultSteps.innerHTML = result.steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("");
  renderInsights(state.scenario, state.mode);
  renderTable(result.rows);
}

function renderTable(rows) {
  if (!rows.length) {
    resultTableHead.innerHTML = "<tr><th>상태</th></tr>";
    resultTableBody.innerHTML = "<tr><td>반환된 mock row가 없습니다.</td></tr>";
    return;
  }

  const columns = Object.keys(rows[0]);
  resultTableHead.innerHTML = `<tr>${columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("")}</tr>`;
  resultTableBody.innerHTML = rows
    .map((row) => `<tr>${columns.map((column) => `<td>${escapeHtml(String(row[column]))}</td>`).join("")}</tr>`)
    .join("");
}

function renderInsights(scenarioKey, mode) {
  const insights = getScenarioInsights(scenarioKey, mode);
  developerInsightTitle.textContent = insights.developerTitle;
  developerInsightBody.textContent = insights.developerBody;
  learnerInsightTitle.textContent = insights.learnerTitle;
  learnerInsightBody.textContent = insights.learnerBody;
}

function getScenarioInsights(scenarioKey, mode) {
  if (scenarioKey === "login") {
    return {
      developerTitle: scenarios.login.developerTitle,
      developerBody:
        mode === "safe"
          ? "로그인 입력이 파라미터로만 전달되면 비밀번호 조건이 잘리지 않는다. 개발자는 인증 쿼리 전체를 prepared statement로 바꿨는지부터 확인해야 한다."
          : "로그인 로직에서 username과 password가 문자열로 이어 붙는 순간 인증 절 자체가 깨질 수 있다. 코드 리뷰에서는 문자열 결합과 주석 우회 가능성을 먼저 찾는다.",
      learnerTitle: scenarios.login.learnerTitle,
      learnerBody:
        mode === "safe"
          ? "같은 문자열이 들어가도 safe mode에서는 구조가 바뀌지 않는다. 왜 'admin' -- 가 관리자 로그인을 만들지 못하는지 safe query를 먼저 읽어 보라."
          : "로그인 우회는 비밀번호를 맞힌 것이 아니라 비밀번호 검사 자체를 끊어낸 결과다. 결과보다 먼저 WHERE 절에서 무엇이 사라졌는지 보라."
    };
  }

  return {
    developerTitle: scenarios.search.developerTitle,
    developerBody:
      mode === "safe"
        ? "검색어가 LIKE 파라미터로만 들어가면 UNION과 OR 1=1도 단순 텍스트가 된다. 검색 기능은 '읽기 전용'처럼 보여도 반드시 파라미터 바인딩이 필요하다."
        : "검색 기능은 입력 필드가 하나뿐이어도 대량 노출 지점이 될 수 있다. 개발자는 검색 API, 목록 조회, 관리자 필터를 같은 위험도로 봐야 한다.",
    learnerTitle: scenarios.search.learnerTitle,
    learnerBody:
      mode === "safe"
        ? "safe mode에서는 검색 결과가 늘어나지 않는다. 즉, 공격 문자열의 핵심은 텍스트 자체가 아니라 쿼리 구조를 바꾸는 능력이라는 점을 기억하라."
        : "검색 실습에서는 '조건이 넓어졌는지', '다른 테이블이 붙었는지', '추가 명령 위험이 생겼는지'를 순서대로 보면 이해가 빠르다."
  };
}

function formatLoginRow(user, reason) {
  return {
    username: user.username,
    role: user.role,
    state: user.state,
    reason
  };
}

function normalizeScenarioValues(values) {
  return Object.fromEntries(
    Object.entries(values).map(([key, value]) => [key, normalizeInput(value)])
  );
}

function normalizeInput(value) {
  return String(value)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s{2,}/g, " ")
    .slice(0, MAX_INPUT_LENGTH);
}

function detectPatterns(text) {
  const normalized = text.toLowerCase();
  const tautology =
    /'\s*or\s*'?\d+'?\s*=\s*'?\d+'?/i.test(text) ||
    /'\s*or\s*'[^']+'\s*=\s*'[^']+'/i.test(text) ||
    /\bor\s+1=1\b/i.test(text);
  const comment = /--|#|\/\*/.test(normalized);
  const union = /\bunion\b[\s\S]*\bselect\b/i.test(text);
  const stacked = /;\s*(drop|delete|update|insert|alter)\b/i.test(text);

  return {
    tautology,
    comment,
    union,
    stacked,
    any: tautology || comment || union || stacked
  };
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setupRevealObserver() {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    {
      threshold: 0.2
    }
  );

  document.querySelectorAll(".reveal").forEach((element) => observer.observe(element));
}
