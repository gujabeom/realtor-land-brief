/* 단지 브리핑 — data/brief.enc 를 비밀번호로 복호화해 보여준다.
 * 암호화 형식은 master/brief.py 와 같다: PBKDF2-SHA256 → AES-256-GCM.
 * '이 기기에서 기억'은 비밀번호가 아니라 도출된 키를 저장한다. */
(() => {
  "use strict";
  const KEY_STORE = "nlb.key.v1";
  const POS_STORE = "nlb.position";
  const GROUP_STORE = "nlb.group";
  const FILTER_STORE = "nlb.filter.v1";
  const BASEMODE_STORE = "nlb.basemode";
  const RANKMODE_STORE = "nlb.rankmode";
  const RANKSCOPE_STORE = "nlb.rankscope";  // 순위 범위: complex(단지별, 기본) / group(선택한 그룹 통합)
  const BASKET_STORE = "nlb.baskets.v1";    // 바구니 (이 기기 브라우저에만 저장)
  const STALE_HOURS = 36;
  const POSITIONS = [
    { id: "buyer", label: "매수 손님 응대" },
    { id: "hunter", label: "급매 발굴" },
    { id: "seller", label: "매도 영업·가격 상담" },
    { id: "market", label: "시장 브리핑·콘텐츠" },
  ];
  const $ = (s) => document.querySelector(s);
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* 저장 불가 환경 */ } },
    del(k) { try { localStorage.removeItem(k); } catch { /* */ } },
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const man = (won) => (won ? Math.round(won / 10000).toLocaleString("ko-KR") : "");
  const pct = (v) => (v == null ? "" : `${v > 0 ? "+" : ""}${(v * 100).toFixed(1)}%`);

  let enc = null;
  let data = null;
  let groupIds = null;   // 선택한 그룹의 단지번호 Set (null = 전체)
  // 필터: 거래방식·대표 평형(여러 개), 가격·월세 범위(만원)
  const TRADES = ["매매", "전세", "월세", "단기임대"];
  const PRICE_STEPS = [5000, 6000, 7000, 8000, 9000, 10000, 20000, 30000, 40000, 50000, 60000, 70000,
    80000, 90000, 100000, 110000, 120000, 130000, 140000, 150000, 160000, 170000, 180000, -180000];
  const RENT_STEPS = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, -200];   // 음수 = '~' (그 이상)
  const FLOORS = ["1층", "저층", "중간층", "고층", "탑층"];
  const COUNTS = [["1", "1개"], ["2", "2개"], ["3", "3개"], ["4", "4개 이상"]];
  const DIRS = ["동", "남동", "서", "남서", "남", "북동", "북", "북서"];
  const TAGS = ["올수리·인테리어", "부분수리", "복층", "급매", "세안고", "로얄", "최상관리", "학교인근"];
  const emptyF = () => ({ trades: [], bands: [], pmin: null, pmax: null, rmin: null, rmax: null,
    floors: [], rooms: [], baths: [], dirs: [], tags: [] });
  let F = emptyF();
  // 층 구분: 1층 / 탑층 / 저층(아래 1/3, 1층 포함) / 중간층 / 고층(위 1/3, 탑층 포함). '저·중·고'로만 공개된 층도 반영
  const floorIs = (x, want) => {
    const f = String(x.floor || ""), n = parseInt(f, 10), t = parseInt(x.totalFloor, 10);
    if (!want) return true;
    if (Number.isNaN(n)) return (want === "저층" && f.startsWith("저")) || (want === "중간층" && f.startsWith("중")) ||
      (want === "고층" && f.startsWith("고"));
    if (want === "1층") return n === 1;
    if (!t) return want === "저층" && n <= 3;
    if (want === "탑층") return n === t;
    if (want === "저층") return n <= t / 3;
    if (want === "중간층") return n > t / 3 && n <= (2 * t) / 3;
    return n > (2 * t) / 3;     // 고층
  };
  const cntIs = (v, want) => !want || (want === "4" ? v >= 4 : v === Number(want));
  // 층수·방 수·욕실 수: 여러 개 고르면 그중 하나라도 맞으면 (예: 저층 + 탑층)
  const anyOf = (list, test) => !list.length || list.some(test);
  const passAttr = (x) => anyOf(F.floors, (w) => floorIs(x, w)) && anyOf(F.rooms, (w) => cntIs(x.rooms || 0, w)) &&
    anyOf(F.baths, (w) => cntIs(x.baths || 0, w)) &&
    (!F.dirs.length || F.dirs.includes(x.dir)) && F.tags.every((t) => (x.tags || []).includes(t));
  const attrOn = () => !!(F.floors.length || F.rooms.length || F.baths.length || F.dirs.length || F.tags.length);
  const inGroupOnly = (x) => !groupIds || groupIds.has(x.complexId);
  const passBase = (x) => (!F.trades.length || F.trades.includes(x.trade)) &&
    (!F.bands.length || F.bands.includes(x.band));
  const passPrice = (x) => {
    const p = x.price ? x.price / 10000 : null, r = x.rent ? x.rent / 10000 : 0;
    if (F.pmin != null && (p == null || p < F.pmin)) return false;
    if (F.pmax != null && (p == null || p > F.pmax)) return false;
    if (F.rmin != null && r < F.rmin) return false;
    if (F.rmax != null && (!r || r > F.rmax)) return false;
    return true;
  };
  const inGroup = (x) => inGroupOnly(x) && passBase(x) && passPrice(x) && passAttr(x);
  const filterCount = () => (F.trades.length ? 1 : 0) + (F.bands.length ? 1 : 0) +
    (F.pmin != null || F.pmax != null ? 1 : 0) + (F.rmin != null || F.rmax != null ? 1 : 0) +
    (F.floors.length ? 1 : 0) + (F.rooms.length ? 1 : 0) + (F.baths.length ? 1 : 0) + (F.dirs.length ? 1 : 0) + (F.tags.length ? 1 : 0);

  // ---------- 복호화 ----------
  async function deriveKey(password, salt, iter) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password),
      "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
      base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }
  async function decryptWith(key) {
    let plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(enc.iv) }, key, b64(enc.ct));
    if (enc.z === "gzip") {   // 마스터가 압축 후 암호화
      const ds = new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"));
      plain = await new Response(ds).arrayBuffer();
    }
    return JSON.parse(new TextDecoder().decode(plain));
  }
  async function tryStoredKey() {
    const raw = store.get(KEY_STORE);
    if (!raw) return false;
    try {
      const s = JSON.parse(raw);
      if (s.salt !== enc.salt || s.iter !== enc.iter) return false;
      const key = await crypto.subtle.importKey("raw", b64(s.key), "AES-GCM", false, ["decrypt"]);
      data = await decryptWith(key);
      return true;
    } catch { store.del(KEY_STORE); return false; }
  }

  async function load() {
    try {
      const r = await fetch(`data/brief.enc?t=${Date.now()}`, { cache: "no-store" });
      if (!r.ok) throw new Error(r.status);
      enc = await r.json();
    } catch (e) {
      showLock("데이터를 불러오지 못했습니다. 잠시 후 다시 열어 주세요.");
      $("#unlockBtn").disabled = true;
      return;
    }
    if (await tryStoredKey()) render(); else showLock("");
  }

  function showLock(msg) {
    $("#app").hidden = true;
    $("#lock").hidden = false;
    $("#lockMsg").textContent = msg;
    if ($("#pw").type !== "password") $("#pwShow").click();   // 잠금 화면은 다시 가린 상태로
    $("#pw").focus();
  }

  $("#lockForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("#unlockBtn");
    btn.disabled = true; btn.textContent = "여는 중…";
    $("#lockMsg").textContent = "";
    try {
      const key = await deriveKey($("#pw").value, b64(enc.salt), enc.iter);
      data = await decryptWith(key);
      if ($("#remember").checked) {
        const raw = await crypto.subtle.exportKey("raw", key);
        store.set(KEY_STORE, JSON.stringify({ salt: enc.salt, iter: enc.iter, key: b64e(raw) }));
      }
      $("#pw").value = "";
      render();
    } catch {
      $("#lockMsg").textContent = "비밀번호가 틀렸습니다.";
    } finally {
      btn.disabled = false; btn.textContent = "열기";
    }
  });
  // 로그아웃: 확인 창 → 기억된 키 삭제 → 비밀번호 화면
  // 비밀번호 보기/숨기기 (입력 중인 글자는 그대로, 커서 위치도 유지)
  $("#pwShow").addEventListener("click", () => {
    const pw = $("#pw"), show = pw.type === "password";
    const a = pw.selectionStart, z = pw.selectionEnd;
    pw.type = show ? "text" : "password";
    $("#pwShow").textContent = show ? "숨기기" : "보기";
    $("#pwShow").setAttribute("aria-pressed", show);
    $("#pwShow").setAttribute("aria-label", show ? "비밀번호 숨기기" : "비밀번호 보기");
    pw.focus();
    try { pw.setSelectionRange(a, z); } catch { /* */ }
  });

  function logout() { store.del(KEY_STORE); data = null; showLock(""); }
  $("#lockBtn").addEventListener("click", () => {
    const dlg = $("#logoutDlg");
    if (typeof dlg.showModal !== "function") {   // <dialog> 미지원 브라우저
      if (window.confirm("로그아웃할까요?")) logout();
      return;
    }
    dlg.returnValue = "";
    dlg.onclose = () => { if (dlg.returnValue === "ok") logout(); };
    dlg.showModal();
  });

  // ---------- 탭 ----------
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((x) => x.setAttribute("aria-selected", x === b));
    document.querySelectorAll(".tab").forEach((t) => { t.hidden = t.id !== `tab-${b.dataset.tab}`; });
    window.scrollTo({ top: 0 });
  }));

  // ---------- 렌더링 ----------
  function render() {
    $("#lock").hidden = true;
    $("#app").hidden = false;
    const m = data.meta;
    const at = m.collectedAt || m.generatedAt;   // 수집 시각 (예전 데이터는 생성 시각)
    const ageH = (Date.now() - Date.parse(at)) / 36e5;
    const ago = ageH < 1 ? `${Math.max(0, Math.floor(ageH * 60))}분 전` : ageH < 48 ? `${Math.floor(ageH)}시간 전` : `${Math.floor(ageH / 24)}일 전`;
    const when = `${at.slice(0, 10)} ${at.slice(11, 13)}시${at.slice(14, 16)}분`;
    $("#asof").textContent = `데이터 기준 ${m.dataDate} · 수집 ${when} (${ago}) · 단지 ${m.complexes}곳`;
    const warns = [];
    if (ageH > STALE_HOURS) warns.push(`데이터가 ${Math.floor(ageH)}시간 전 것입니다. 마스터 PC 수집을 확인하세요.`);
    if (m.failed && m.failed.length) warns.push(`수집이 불완전한 단지: ${m.failed.join(", ")}`);
    $("#warn").hidden = !warns.length;
    $("#warn").textContent = warns.join(" ");
    setupGroups();
    setupFilter();
    setupBasket();
    renderLists();
    receiveBasket();   // 주소에 #bk=… 가 있으면 바구니 받기
  }

  function renderLists() {
    renderBasket();
    renderToday();
    renderHot();
    renderChanges();
    renderMarket();
  }

  // 단지 그룹 (마스터 config/complexes.txt 의 '## 그룹명' 줄)
  function setupGroups() {
    const groups = data.groups || [];
    const sel = $("#fGroup");
    sel.hidden = !groups.length;
    sel.innerHTML = `<option value="">전체 단지</option>` +
      groups.map((g, i) => `<option value="${i}">${esc(g.name)}</option>`).join("");
    const saved = store.get(GROUP_STORE);
    const idx = groups.findIndex((g) => g.name === saved);
    sel.value = idx >= 0 ? String(idx) : "";
    const apply = () => {
      const g = groups[Number(sel.value)];
      groupIds = sel.value !== "" && g ? new Set(g.ids) : null;
    };
    apply();
    // 그룹(큰 분류)을 바꾸면 급매 탭의 단지·세부 평형 선택은 초기화
    const LOCAL = ["#fComplex", "#fSupply", "#pComplex", "#pSupply"];
    const hasLocal = () => LOCAL.some((id) => ($(id)._sel ? $(id)._sel.size : $(id).value));
    const resetLocal = () => {
      LOCAL.forEach((id) => { if ($(id)._sel) $(id)._sel.clear(); else $(id).value = ""; });
      $("#pTrade").value = ""; chg = null;
    };
    let clicks = 0, changed = false;
    sel.onchange = () => {
      changed = true;
      apply();
      if (sel.value === "") store.del(GROUP_STORE); else store.set(GROUP_STORE, groups[Number(sel.value)].name);
      resetLocal();
      renderLists();
    };
    // 같은 그룹을 다시 골라도 초기화 (PC 브라우저: 목록을 열고 닫는 두 번째 클릭으로 판단)
    sel.addEventListener("click", () => {
      clicks += 1;
      if (clicks % 2 === 0) {
        if (!changed && hasLocal()) { resetLocal(); renderLists(); }
        changed = false;
      }
    });
    const disarm = () => { clicks = 0; changed = false; };
    sel.addEventListener("blur", disarm);
    sel.addEventListener("keydown", (e) => { if (e.key === "Escape" || e.key === "Tab") disarm(); });
  }

  // ---------- 필터 패널 ----------
  const manText = (m) => {
    if (m == null) return "";
    const eok = Math.floor(m / 10000), rest = Math.round(m % 10000);
    return eok ? `${eok}억${rest ? ` ${rest.toLocaleString("ko-KR")}` : ""}` : `${rest.toLocaleString("ko-KR")}만`;
  };
  const stepLabel = (v, rent) => {
    const a = Math.abs(v);
    const t = rent ? (a >= 100 ? `${a / 100}백` : String(a)) : (a >= 10000 ? `${a / 10000}억` : `${a / 1000}천`);
    return v < 0 ? `${t}~` : t;
  };
  const parseMan = (txt) => {   // "3억", "3.5억", "3억 5000", "35000" → 만원
    const t = String(txt || "").replace(/[,\s]/g, "");
    if (!t) return null;
    const m = t.match(/^(?:(\d+(?:\.\d+)?)억)?(\d+(?:\.\d+)?)?(?:만|만원)?$/);
    if (!m || (!m[1] && !m[2])) return null;
    return Math.round((m[1] ? parseFloat(m[1]) * 10000 : 0) + (m[2] ? parseFloat(m[2]) : 0));
  };
  function saveFilter() { store.set(FILTER_STORE, JSON.stringify(F)); }
  function loadFilter() {
    try {
      const f = JSON.parse(store.get(FILTER_STORE) || "{}");
      F = { trades: (f.trades || []).filter((t) => TRADES.includes(t)),
        bands: (f.bands || []).filter((b) => (data.bands || []).includes(b)),
        pmin: f.pmin ?? null, pmax: f.pmax ?? null, rmin: f.rmin ?? null, rmax: f.rmax ?? null,
        floors: [].concat(f.floors || f.floor || []).filter((v) => FLOORS.includes(v)),
        rooms: [].concat(f.rooms || []).filter((v) => COUNTS.some((c) => c[0] === v)),
        baths: [].concat(f.baths || []).filter((v) => COUNTS.some((c) => c[0] === v)),
        dirs: (f.dirs || []).filter((d) => DIRS.includes(d)), tags: (f.tags || []).filter((t) => TAGS.includes(t)) };
    } catch { /* 기본값 */ }
  }
  function stepClick(kind, v) {
    const lo = kind === "p" ? "pmin" : "rmin", hi = kind === "p" ? "pmax" : "rmax";
    if (v < 0) { F[lo] = -v; F[hi] = null; }
    else if (F[lo] == null || F[hi] != null) { F[lo] = v; F[hi] = null; }
    else if (v >= F[lo]) F[hi] = v;
    else { F[hi] = F[lo]; F[lo] = v; }
    filterChanged();
  }
  function drawFilter() {
    const chip = (vals, sel, key) => vals.map((v) =>
      `<button type="button" aria-pressed="${sel.includes(v)}" data-${key}="${esc(v)}">${esc(v)}</button>`).join("");
    $("#fpTrade").innerHTML = chip(TRADES, F.trades, "t");
    const rng = data.bandRanges || {};
    $("#fpBand").innerHTML = (data.bands || []).map((v) => {
      const r = rng[v] && rng[v] !== v ? `<small>${esc(rng[v])}</small>` : "";
      return `<button type="button" class="band-chip" aria-pressed="${F.bands.includes(v)}" data-b="${esc(v)}"><span>${esc(v)}</span>${r}</button>`;
    }).join("");
    $("#fpTrade").querySelectorAll("button").forEach((b) => { b.onclick = () => toggle("trades", b.dataset.t); });
    $("#fpBand").querySelectorAll("button").forEach((b) => { b.onclick = () => toggle("bands", b.dataset.b); });
    const grid = (el, steps, rent, lo, hi) => {
      el.innerHTML = steps.map((v) => {
        const a = Math.abs(v);
        const edge = a === lo || a === hi;
        const on = lo != null && (hi != null ? a >= lo && a <= hi : (v < 0 ? a === lo : a === lo));
        return `<button type="button" class="${edge ? "edge" : on ? "on" : ""}" data-v="${v}">${stepLabel(v, rent)}</button>`;
      }).join("");
      el.querySelectorAll("button").forEach((b) => { b.onclick = () => stepClick(rent ? "r" : "p", Number(b.dataset.v)); });
    };
    // 여러 개 고르는 칸 + '전체'(= 선택 해제)
    const multi = (el, key, opts) => {
      el.innerHTML = [["", "전체"], ...opts].map(([v, t]) =>
        `<button type="button" aria-pressed="${v ? F[key].includes(v) : !F[key].length}" data-v="${esc(v)}">${esc(t)}</button>`).join("");
      el.querySelectorAll("button").forEach((b) => {
        b.onclick = () => { if (b.dataset.v) toggle(key, b.dataset.v); else { F[key] = []; filterChanged(); } };
      });
    };
    multi($("#fpFloor"), "floors", FLOORS.map((v) => [v, v]));
    multi($("#fpRooms"), "rooms", COUNTS);
    multi($("#fpBaths"), "baths", COUNTS);
    $("#fpDir").innerHTML = chip(DIRS, F.dirs, "d");
    $("#fpDir").querySelectorAll("button").forEach((b) => { b.onclick = () => toggle("dirs", b.dataset.d); });
    $("#fpTag").innerHTML = chip(TAGS, F.tags, "g");
    $("#fpTag").querySelectorAll("button").forEach((b) => { b.onclick = () => toggle("tags", b.dataset.g); });
    grid($("#fpPriceGrid"), PRICE_STEPS, false, F.pmin, F.pmax);
    grid($("#fpRentGrid"), RENT_STEPS, true, F.rmin, F.rmax);
    $("#fpPmin").value = F.pmin != null ? manText(F.pmin) : "";
    $("#fpPmax").value = F.pmax != null ? manText(F.pmax) : "";
    $("#fpRmin").value = F.rmin ?? "";
    $("#fpRmax").value = F.rmax ?? "";
    // 요약 줄 · 배지
    const n = filterCount();
    $("#filterCount").hidden = !n;
    $("#filterCount").textContent = n;
    $("#filterBtn").classList.toggle("active", n > 0);
    const parts = [];
    if (F.trades.length) parts.push(F.trades.join("·"));
    if (F.bands.length) parts.push(F.bands.map((b) => (data.bandRanges || {})[b] || b).join("·"));
    if (F.pmin != null || F.pmax != null) parts.push(`${manText(F.pmin) || "0"} ~ ${manText(F.pmax) || ""}`.trim());
    if (F.rmin != null || F.rmax != null) parts.push(`월세 ${F.rmin ?? 0} ~ ${F.rmax ?? ""}`.trim());
    const cnt = (l) => l.map((v) => (v === "4" ? "4개 이상" : v + "개")).join("·");
    if (F.floors.length) parts.push(F.floors.join("·"));
    if (F.rooms.length) parts.push(`방 ${cnt(F.rooms)}`);
    if (F.baths.length) parts.push(`욕실 ${cnt(F.baths)}`);
    if (F.dirs.length) parts.push(F.dirs.map((d) => d + "향").join("·"));
    if (F.tags.length) parts.push(F.tags.join("·"));
    $("#filterSummary").hidden = !parts.length;
    $("#filterSummary").innerHTML = parts.map((p) => `<span>${esc(p)}</span>`).join("") +
      (parts.length ? `<button type="button" id="fsClear">조건 삭제</button>` : "");
    const c = $("#fsClear");
    if (c) c.onclick = resetFilter;
  }
  function toggle(key, v) {
    F[key] = F[key].includes(v) ? F[key].filter((x) => x !== v) : F[key].concat(v);
    filterChanged();
  }
  function resetFilter() {
    F = emptyF();
    filterChanged();
  }
  function filterChanged() { saveFilter(); drawFilter(); renderLists(); }
  function setupFilter() {
    loadFilter();
    const open = (on) => {
      $("#filterPanel").hidden = !on;
      $("#filterBtn").setAttribute("aria-expanded", on);
      if (on) $("#filterPanel").scrollIntoView({ block: "nearest" });
    };
    $("#filterBtn").onclick = () => open($("#filterPanel").hidden);
    $("#fpClose").onclick = () => open(false);
    $("#fpReset").onclick = resetFilter;
    const inp = (id, key, parse) => {
      $(id).onchange = () => { F[key] = parse($(id).value); filterChanged(); };
    };
    inp("#fpPmin", "pmin", parseMan);
    inp("#fpPmax", "pmax", parseMan);
    inp("#fpRmin", "rmin", (t) => (String(t).trim() === "" ? null : Math.max(0, parseInt(t, 10) || 0)));
    inp("#fpRmax", "rmax", (t) => (String(t).trim() === "" ? null : Math.max(0, parseInt(t, 10) || 0)));
    drawFilter();
  }

  // ---------- 추천 행동 (필터된 데이터로 브라우저에서 계산) ----------
  function buildActions(v) {
    const out = { buyer: [], hunter: [], seller: [], market: [] };
    const nNew = v.news.length, nDrop = v.drops.length, nGone = v.gone.length;
    if (nNew) {
      const cnt = {};
      v.news.forEach((u) => { cnt[u.complex] = (cnt[u.complex] || 0) + 1; });
      const [bn, bc] = Object.entries(cnt).sort((a, b) => b[1] - a[1])[0];
      out.buyer.push(`어제 신규 ${nNew}건. ${bn}에서 ${bc}건으로 가장 많습니다.`);
    }
    v.baselines.filter((b) => b.inZone).slice(0, 3).forEach((b) =>
      out.buyer.push(`${b.complex} ${b.supply}㎡ ${b.trade}: 거래권(${b.zoneText}) 매물 ${b.inZone}건을 먼저 안내하세요.`));
    if (!out.buyer.length) out.buyer.push("신규 매물이 없습니다. '급매' 탭 상위 매물로 상담을 준비하세요.");
    if (nDrop) out.hunter.push(`어제 가격 인하 ${nDrop}건. '변동' 탭에서 인하 폭이 큰 순서로 확인하세요.`);
    const top = v.hot[0];
    if (top) out.hunter.push(`점수 1위: ${top.complex} ${top.supply}㎡ ${top.dong}동 ${top.floor}층 ${top.priceText} — ${(top.reasons || []).slice(0, 3).join(", ")}`);
    if (!out.hunter.length) out.hunter.push("이 조건에서는 눈에 띄는 급매 신호가 없습니다.");
    if (nGone) out.seller.push(`어제 사라진 매물 ${nGone}건(거래 추정). 마지막 호가를 매도 상담 근거로 쓰세요.`);
    const withBase = v.baselines.filter((b) => b.baseline);
    withBase.slice(0, 3).forEach((b) => out.seller.push(
      `${b.complex} ${b.supply}㎡ ${b.trade}: 추정 거래가 ${b.baselineText}, 최저 호가 ${b.minText}, 경쟁 매물 ${b.active}건.`));
    if (!withBase.length) out.seller.push("추정 거래가(기준선)는 사라진 매물이 쌓이면 표시됩니다. 지금은 최저 호가와 경쟁 매물 수를 근거로 쓰세요.");
    out.market.push(`단지 ${v.cards.length}곳, 매물 ${v.cards.reduce((a, c) => a + c.active, 0)}건 (신규 ${nNew} · 인하 ${nDrop} · 사라짐 ${nGone}).`);
    const tr = v.trends;
    if (tr.length >= 2 && tr[tr.length - 2].active) {
      const d = tr[tr.length - 1].active - tr[tr.length - 2].active;
      out.market.push(`지난주 대비 매물 ${d > 0 ? "+" : ""}${d}건 (${pct(d / tr[tr.length - 2].active)}).`);
    }
    return out;
  }

  function renderToday() {
    const cur = store.get(POS_STORE) || "buyer";
    $("#positions").innerHTML = POSITIONS.map((p) =>
      `<button type="button" role="radio" aria-checked="${p.id === cur}" data-pos="${p.id}">${esc(p.label)}</button>`).join("");
    $("#positions").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
      store.set(POS_STORE, b.dataset.pos); renderToday();
    }));
    // 단지별 카드: 활성 매물(units) · 어제 변동을 필터 조건으로 집계
    const units = (data.units || []).map((r) => ({ complexId: r[0], trade: r[1], band: r[2], price: r[3], rent: r[4],
      floor: r[5], totalFloor: r[6], rooms: r[7], baths: r[8], dir: r[9], tags: r[10] ? String(r[10]).split("·") : [] }))
      .filter(inGroup);
    const news = (data.new || []).filter(inGroup), drops = (data.drops || []).filter(inGroup),
      gone = (data.gone || []).filter(inGroup);
    const filtered = filterCount() > 0;
    const cards = data.summary.filter(inGroupOnly).map((s) => {
      const us = units.filter((u) => u.complexId === s.complexId);
      const c = (list) => list.filter((u) => u.complexId === s.complexId).length;
      return { ...s, active: us.length, sale: us.filter((u) => u.trade === "매매").length,
        jeonse: us.filter((u) => u.trade === "전세").length,
        monthly: us.filter((u) => u.trade === "월세" || u.trade === "단기임대").length,
        new: c(news), drop: c(drops), gone: c(gone) };
    }).filter((s) => !filtered || s.active || s.new || s.drop || s.gone);
    const acts = buildActions({ cards, news, drops, gone, hot: hotList().filter(inGroup),
      baselines: (data.baselines || []).filter((b) => inGroupOnly(b) && passBase(b)),
      trends: !groupIds && !filtered ? (data.trends || []) : [] })[cur] || [];
    $("#actions").innerHTML = acts.map((a) => `<li>${esc(a)}</li>`).join("") ||
      `<li class="muted">오늘은 추천할 행동이 없습니다.</li>`;
    $("#summaryNote").textContent = filtered ? "필터 조건 기준 · 어제 대비" : "어제 대비";
    // 카드 안 숫자를 누르면 그 매물로 이동 (지금 필터 조건 그대로 + 단지·거래만 더해서 → 숫자와 목록 건수가 같다)
    const lnk = (n, attrs, text, cls = "") => n
      ? `<button type="button" class="lnk ${cls}" ${attrs}>${text}</button>` : `<span class="${cls}">${text}</span>`;
    $("#summary").innerHTML = (cards.map((s) => `
      <div class="card${s.scannedToday && s.complete ? "" : " stale"}" data-cid="${s.complexId}" data-name="${esc(s.complex)}">
        <h3>${lnk(s.active, `data-go="price"`, esc(s.complex))}</h3>
        <div class="big">${lnk(s.active, `data-go="price"`, `${s.active}<span class="muted small"> 건</span>`)}</div>
        <div class="muted small">${lnk(s.sale, `data-go="price" data-trade="매매"`, `매매 ${s.sale}`)} ·
          ${lnk(s.jeonse, `data-go="price" data-trade="전세"`, `전세 ${s.jeonse}`)} ·
          ${lnk(s.monthly, `data-go="price" data-trade="월세"`, `월세 ${s.monthly}`)}</div>
        <div class="row">
          ${lnk(s.new, `data-go="new"`, `신규 ${s.new}`, "tag-new")}
          ${lnk(s.drop, `data-go="drop"`, `인하 ${s.drop}`, "tag-drop")}
          ${lnk(s.gone, `data-go="gone"`, `사라짐 ${s.gone}`, "tag-gone")}
        </div>
      </div>`).join("")) || `<p class="empty">이 조건의 매물이 없습니다.</p>`;
    $("#summary").querySelectorAll(".lnk").forEach((b) => {
      b.onclick = () => {
        const card = b.closest(".card"), go = b.dataset.go;
        if (go === "price") showInPrice(card.dataset.name, b.dataset.trade || "");
        else showInChanges(Number(card.dataset.cid), card.dataset.name, go);
      };
    });
  }

  const goTab = (name) => document.querySelector(`.tabs button[data-tab="${name}"]`).click();
  function showInPrice(name, trade) {
    $("#pComplex")._sel = new Set([name]);
    $("#pSupply").value = ""; $("#pOurs").value = ""; $("#pTrade").value = trade; $("#prSort").value = "price";
    renderUnitTab(PRICE_TAB);
    goTab("price");
  }
  let chg = null;   // 변동 탭에서 한 단지만 볼 때 {id, name}
  function showInChanges(id, name, section) {
    chg = { id, name };
    renderChanges();
    goTab("changes");
    const target = { drop: "#dropList", new: "#newList", gone: "#goneList" }[section];
    const h = $(target) && $(target).previousElementSibling;
    if (h && section !== "drop") h.scrollIntoView({ block: "start" });
  }

  // 거래방식 배지 · 가격 색 (매매=흰 배경, 전세=주황, 월세=초록, 단기임대=보라)
  const TRADE_CLASS = { "매매": "sale", "전세": "jeonse", "월세": "monthly", "단기임대": "short" };
  const tradeBadge = (t) => t ? `<span class="tb tb-${TRADE_CLASS[t] || "sale"}">${esc(t)}</span>` : "";

  // ---------- 바구니 (고객별로 매물을 모아 브리핑·답사) ----------
  const SNAP_KEYS = ["unitId", "complexId", "complex", "trade", "supply", "py", "pyeong", "dong", "floor",
    "totalFloor", "direction", "priceText", "price", "rent", "article", "band", "feature", "ads"];
  const wonText = (won) => {
    const m = Math.round((won || 0) / 10000);
    if (!m) return "";
    const eok = Math.floor(m / 10000), rest = m % 10000;
    return eok ? `${eok}억${rest ? ` ${rest.toLocaleString("ko-KR")}` : ""}` : rest.toLocaleString("ko-KR");
  };
  const adPrice = (a) => wonText(a[1]) + (a[2] ? `/${Math.round(a[2] / 10000).toLocaleString("ko-KR")}` : "");
  const nvUrl = (cid, art) => `https://new.land.naver.com/complexes/${encodeURIComponent(cid)}?a=APT:ABYG:JGC&e=RETAIL&articleNo=${encodeURIComponent(art)}`;
  // 중개사 목록 (바구니): 우리 사무소 먼저, 낮은 호가 순. 전화번호는 목록 데이터에 없어 네이버 지도 검색으로 연결
  function adsHtml(u) {
    const ads = u.ads || [];
    if (!ads.length) return "";
    const ps = ads.map((a) => a[1]).filter(Boolean);
    const lo = Math.min(...ps), hi = Math.max(...ps);
    const range = ps.length ? (lo === hi ? wonText(lo) : `${wonText(lo)} ~ ${wonText(hi)}`) : "";
    return `<details class="bk-ads"><summary>중개사 ${ads.length}곳${range ? ` · 호가 ${esc(range)}` : ""}</summary><ul>` +
      ads.map((a) => `<li${a[4] ? ' class="ours"' : ""}>
        <span class="bk-ad-name">${a[4] ? '<span class="badge-ours">우리</span> ' : ""}${esc(a[0] || "(이름 없음)")}</span>
        <span class="bk-ad-price${a[1] !== lo ? " hi" : ""}">${esc(adPrice(a))}</span>
        <span class="bk-ad-links">${a[3] && u.complexId ? `<a href="${nvUrl(u.complexId, a[3])}" target="_blank" rel="noopener noreferrer">광고</a>` : ""}
        ${a[0] ? `<a href="https://map.naver.com/p/search/${encodeURIComponent(a[0])}" target="_blank" rel="noopener noreferrer">연락처</a>` : ""}</span>
      </li>`).join("") + `</ul></details>`;
  }
  function loadBaskets() {
    try {
      const b = JSON.parse(store.get(BASKET_STORE) || "null");
      if (b && Array.isArray(b.list) && b.list.length) return b;
    } catch { /* 새로 */ }
    return { cur: "b1", seq: 1, list: [{ id: "b1", name: "바구니 1", items: [] }] };
  }
  let BK = loadBaskets();
  const saveBk = () => store.set(BASKET_STORE, JSON.stringify(BK));
  const curBk = () => BK.list.find((b) => b.id === BK.cur) || BK.list[0];
  const inBk = (uid) => curBk().items.some((i) => i.unitId === uid);
  let unitById = new Map(), goneById = new Map();
  const indexUnits = () => {
    unitById = new Map((data.hot || []).map((h) => [h.unitId, h]));
    goneById = new Map((data.gone || []).map((h) => [h.unitId, h]));
  };
  const bkBtn = (u, opt) => (u.unitId == null ? "" : opt.basket
    ? `<button type="button" class="bk-btn on" data-uid="${u.unitId}" title="바구니에서 빼기">빼기</button>`
    : `<button type="button" class="bk-btn${inBk(u.unitId) ? " on" : ""}" data-uid="${u.unitId}">${inBk(u.unitId) ? "✓ 담김" : "+ 담기"}</button>`);
  function toggleBk(uid) {
    const b = curBk(), i = b.items.findIndex((x) => x.unitId === uid);
    if (i >= 0) b.items.splice(i, 1);
    else {
      const u = unitById.get(uid);
      if (!u) return;
      const snap = {};
      SNAP_KEYS.forEach((k) => { if (u[k] != null) snap[k] = u[k]; });
      b.items.push({ unitId: uid, savedAt: new Date().toISOString(), snap, memo: "" });
    }
    saveBk();
    document.querySelectorAll(`.bk-btn[data-uid="${uid}"]`).forEach((x) => {
      if (x.closest("#bkList")) return;
      const on = inBk(uid);
      x.classList.toggle("on", on);
      x.textContent = on ? "✓ 담김" : "+ 담기";
    });
    renderBasket();
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest(".bk-btn");
    if (b) toggleBk(Number(b.dataset.uid));
  });
  function bkText(work = false) {
    const b = curBk();
    const lines = [`[${b.name}] ${data.meta.dataDate} 기준 · ${b.items.length}건`];
    b.items.forEach((it, i) => {
      const u = unitById.get(it.unitId) || it.snap;
      const floor = u.totalFloor ? `${u.floor}/${u.totalFloor}층` : `${u.floor || ""}층`;
      lines.push(`${i + 1}) ${u.complex} ${u.dong ? u.dong + "동 " : ""}${floor} · ${u.supply}㎡${u.py ? `(${u.py}평)` : ""} ${u.direction || ""} · ${u.trade} ${u.priceText}` +
        (unitById.has(it.unitId) ? "" : " (현재 목록에 없음)"));
      if (it.memo) lines.push(`   메모: ${it.memo}`);
      if (work && (u.ads || []).length) {
        lines.push(`   중개사 ${u.ads.length}곳: ` + u.ads.map((a) => `${a[0]}(${adPrice(a)})`).join(", "));
      }
      if (u.article && u.complexId) lines.push(`   https://new.land.naver.com/complexes/${u.complexId}?a=APT:ABYG:JGC&e=RETAIL&articleNo=${u.article}`);
    });
    return lines.join("\n");
  }
  async function copyText(t) {
    try { await navigator.clipboard.writeText(t); return true; } catch { /* 아래 방법 */ }
    const ta = document.createElement("textarea");
    ta.value = t; document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { /* */ }
    ta.remove();
    return ok;
  }
  function renderBasket() {
    if (!data) return;
    indexUnits();
    const b = curBk();
    const n = b.items.length;
    $("#bkCount").hidden = !n;
    $("#bkCount").textContent = n;
    $("#bkSel").innerHTML = BK.list.map((x) =>
      `<option value="${esc(x.id)}"${x.id === b.id ? " selected" : ""}>${esc(x.name)} (${x.items.length})</option>`).join("");
    $("#bkDel").disabled = BK.list.length < 2;
    $("#bkCopy").disabled = $("#bkCopyWork").disabled = $("#bkClear").disabled = $("#bkShare").disabled = !n;
    $("#bkList").innerHTML = b.items.map((it, i) => {
      const cur = unitById.get(it.unitId), gone = goneById.get(it.unitId);
      const u = cur || { ...it.snap, reasons: [] };
      let status = "";
      if (!cur) status = `<p class="bk-status warn-text">${gone ? "사라진 매물 (거래 추정)" : "오늘 목록에 없음 (광고 내림·거래 등)"} · 담을 때 ${esc(it.snap.priceText || "")}</p>`;
      else if (it.snap.price && cur.price !== it.snap.price) {
        status = `<p class="bk-status ${cur.price < it.snap.price ? "down" : "up"}">담을 때 ${esc(it.snap.priceText)} → 지금 ${esc(cur.priceText)}</p>`;
      }
      const extra = `${status}${adsHtml(u)}<div class="bk-tools">
          <input class="bk-memo" data-uid="${it.unitId}" value="${esc(it.memo || "")}" placeholder="메모 (방문 시간, 동호수 확인, 손님 반응 등)">
          <button type="button" class="ghost bk-mv" data-i="${i}" data-d="-1" title="위로"${i ? "" : " disabled"}>↑</button>
          <button type="button" class="ghost bk-mv" data-i="${i}" data-d="1" title="아래로"${i < n - 1 ? "" : " disabled"}>↓</button>
        </div>`;
      return itemHtml(u, { score: !!cur, basket: true, extra });
    }).join("") || `<p class="empty">바구니가 비어 있습니다. 급매·가격·변동 탭에서 매물의 '+ 담기'를 누르세요.</p>`;
    $("#bkList").querySelectorAll(".bk-memo").forEach((inp) => {
      inp.onchange = () => {
        const it = curBk().items.find((x) => x.unitId === Number(inp.dataset.uid));
        if (it) { it.memo = inp.value.trim(); saveBk(); }
      };
    });
    $("#bkList").querySelectorAll(".bk-mv").forEach((btn) => {
      btn.onclick = () => {
        const items = curBk().items, i = Number(btn.dataset.i), j = i + Number(btn.dataset.d);
        if (j < 0 || j >= items.length) return;
        [items[i], items[j]] = [items[j], items[i]];
        saveBk(); renderBasket();
      };
    });
  }
  // ---- 다른 기기로 보내기: 바구니(매물 번호·메모·순서)를 링크 주소의 # 뒤에 담는다 (# 뒤는 서버로 전송되지 않음) ----
  const b64u = (buf) => b64e(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64u = (t) => b64(t.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (t.length % 4)) % 4));
  const pipeBytes = async (bytes, stream) =>
    new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
  async function packBasket(b) {
    const json = JSON.stringify({ v: 1, n: b.name, i: b.items.map((it) => (it.memo ? [it.unitId, it.memo] : [it.unitId])) });
    const raw = new TextEncoder().encode(json);
    if (typeof CompressionStream === "function") return "1." + b64u(await pipeBytes(raw, new CompressionStream("deflate-raw")));
    return "0." + b64u(raw);
  }
  async function unpackBasket(t) {
    const [ver, body] = [t.slice(0, 1), t.slice(2)];
    let bytes = unb64u(body);
    if (ver === "1") bytes = await pipeBytes(bytes, new DecompressionStream("deflate-raw"));
    const o = JSON.parse(new TextDecoder().decode(bytes));
    if (!o || !Array.isArray(o.i)) throw new Error("형식 오류");
    return o;
  }
  async function shareBasket() {
    const b = curBk();
    const url = `${location.origin}${location.pathname}#bk=${await packBasket(b)}`;
    $("#shareTitle").textContent = `'${b.name}' 보내기 (${b.items.length}건)`;
    $("#shareUrl").value = url;
    let svg = "";
    try {
      const qr = qrcode(0, "L");   // 0 = 크기 자동
      qr.addData(url);
      qr.make();
      svg = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
    } catch { svg = ""; }
    $("#shareQr").innerHTML = svg || `<p class="muted small">매물이 너무 많아 QR로 만들 수 없습니다. '링크 복사'나 '공유'를 쓰세요.</p>`;
    $("#shareDense").hidden = !svg || url.length < 900;
    $("#shareNative").hidden = typeof navigator.share !== "function";
    const dlg = $("#shareDlg");
    if (typeof dlg.showModal === "function") dlg.showModal(); else window.prompt("이 링크를 다른 기기에서 여세요", url);
  }
  async function receiveBasket() {
    const m = location.hash.match(/^#bk=([01]\.[A-Za-z0-9_-]+)$/);
    if (!m || !data) return;
    history.replaceState(null, "", location.pathname + location.search);   // 주소창에서 지움
    let o;
    try { o = await unpackBasket(m[1]); } catch { window.alert("바구니 링크를 읽지 못했습니다. 링크가 잘렸는지 확인하세요."); return; }
    indexUnits();
    const items = o.i.map(([uid, memo]) => {
      const u = unitById.get(uid) || goneById.get(uid);
      const snap = {};
      if (u) SNAP_KEYS.forEach((k) => { if (u[k] != null) snap[k] = u[k]; });
      else Object.assign(snap, { unitId: uid, complex: "(오늘 데이터에 없는 매물)" });
      return { unitId: uid, savedAt: new Date().toISOString(), snap, memo: memo || "" };
    });
    const name = String(o.n || "받은 바구니").slice(0, 60);
    const choose = () => new Promise((res) => {
      const dlg = $("#recvDlg");
      if (typeof dlg.showModal !== "function") { res(window.confirm(`'${name}' ${items.length}건을 새 바구니로 추가할까요?`) ? "new" : ""); return; }
      $("#recvText").textContent = `'${name}' 바구니 ${items.length}건을 받았습니다.`;
      $("#recvMerge").textContent = `지금 바구니('${curBk().name}')에 합치기`;
      dlg.returnValue = "";
      dlg.onclose = () => res(dlg.returnValue);
      dlg.showModal();
    });
    const how = await choose();
    if (how === "new") {
      const same = BK.list.find((x) => x.name === name);
      const nm = same ? `${name} (받음)` : name;
      BK.seq = (BK.seq || BK.list.length) + 1;
      const id = `b${BK.seq}_${Date.now().toString(36)}`;
      BK.list.push({ id, name: nm, items });
      BK.cur = id;
    } else if (how === "merge") {
      const b = curBk();
      items.forEach((it) => {
        const ex = b.items.find((x) => x.unitId === it.unitId);
        if (!ex) b.items.push(it);
        else if (it.memo && !ex.memo) ex.memo = it.memo;
      });
    } else return;
    saveBk();
    renderLists();
    goTab("basket");
  }

  function setupBasket() {
    $("#bkShare").onclick = shareBasket;
    $("#shareCopy").onclick = async () => {
      const ok = await copyText($("#shareUrl").value);
      $("#shareMsg").textContent = ok ? "링크를 복사했습니다." : "복사하지 못했습니다. 주소를 길게 눌러 복사하세요.";
    };
    $("#shareNative").onclick = () => {
      navigator.share({ title: "단지 브리핑 바구니", url: $("#shareUrl").value }).catch(() => { /* 취소 */ });
    };
    window.addEventListener("hashchange", receiveBasket);
    $("#bkSel").onchange = () => { BK.cur = $("#bkSel").value; saveBk(); renderLists(); };
    $("#bkNew").onclick = () => {
      const name = (window.prompt("새 바구니 이름 (예: 김OO 고객 34평 매매)", `바구니 ${BK.list.length + 1}`) || "").trim();
      if (!name) return;
      BK.seq = (BK.seq || BK.list.length) + 1;
      const id = `b${BK.seq}_${Date.now().toString(36)}`;
      BK.list.push({ id, name, items: [] });
      BK.cur = id; saveBk(); renderLists();
    };
    $("#bkRename").onclick = () => {
      const b = curBk();
      const name = (window.prompt("바구니 이름", b.name) || "").trim();
      if (name) { b.name = name; saveBk(); renderBasket(); }
    };
    $("#bkDel").onclick = () => {
      const b = curBk();
      if (BK.list.length < 2 || !window.confirm(`'${b.name}' 바구니를 삭제할까요? (담긴 ${b.items.length}건)`)) return;
      BK.list = BK.list.filter((x) => x !== b);
      BK.cur = BK.list[0].id; saveBk(); renderLists();
    };
    $("#bkClear").onclick = () => {
      const b = curBk();
      if (!window.confirm(`'${b.name}'의 매물 ${b.items.length}건을 모두 뺄까요?`)) return;
      b.items = []; saveBk(); renderLists();
    };
    $("#bkCopyWork").onclick = async () => {
      const ok = await copyText(bkText(true));
      $("#bkMsg").textContent = ok ? "중개사 목록까지 복사했습니다 (내부 업무용)." : "복사하지 못했습니다.";
      setTimeout(() => { $("#bkMsg").textContent = ""; }, 4000);
    };
    $("#bkCopy").onclick = async () => {
      const ok = await copyText(bkText());
      $("#bkMsg").textContent = ok ? "복사했습니다. 카톡·문자에 붙여넣으세요." : "복사하지 못했습니다.";
      setTimeout(() => { $("#bkMsg").textContent = ""; }, 4000);
    };
  }

  // 네이버 부동산 매물 화면 (사라진 매물은 광고가 내려가 열리지 않으므로 생략)
  const naverLink = (u, opt) => (u.article && u.complexId && !opt.gone
    ? `<a class="nv-btn" href="https://new.land.naver.com/complexes/${encodeURIComponent(u.complexId)}?a=APT:ABYG:JGC&e=RETAIL&articleNo=${encodeURIComponent(u.article)}" target="_blank" rel="noopener noreferrer">네이버 부동산</a>`
    : "");

  function itemHtml(u, opt = {}) {
    const tcls = TRADE_CLASS[u.trade] || "sale";
    const ours = u.ours ? `<span class="badge-ours">우리</span>` : "";
    const floor = u.totalFloor ? `${u.floor}/${u.totalFloor}층` : `${u.floor || "-"}층`;
    const meta = [u.supply && `${u.supply}㎡${u.pyeong ? ` (${u.pyeong}평)` : ""}`,
      u.dong && `${u.dong}동`, floor, u.direction, u.brokerCount && `중개사 ${u.brokerCount}`,
      u.daysOnMarket != null && `노출 ${u.daysOnMarket}일`].filter(Boolean).join(" · ");
    let price = esc(u.priceText || "");
    if (opt.change && u.oldText) {
      price = `<span class="old">${esc(u.oldText)}</span>${esc(u.newText)}` +
        (u.change ? `<span class="chg">${u.change > 0 ? "+" : "-"}${man(Math.abs(u.change))} (${pct(u.changePct)})</span>` : "");
    }
    if (opt.gone) price = esc(u.oldText || u.priceText || "");
    const reasons = (u.reasons || []).map((r) => `<span>${esc(r)}</span>`).join("");
    return `<article class="item${u.ours ? " ours" : ""}${opt.score ? "" : " noscore"}">
      ${opt.score ? `<div class="score" title="점수">${Math.round(u.score)}</div>` : ""}
      <div class="title">${tradeBadge(u.trade)}${esc(u.complex)}${ours}${naverLink(u, opt)}${opt.gone ? "" : bkBtn(u, opt)}</div>
      <div class="price pr-${tcls}">${price}</div>
      <div class="meta">${esc(meta)}</div>
      ${reasons ? `<div class="reasons">${reasons}</div>` : ""}
      ${u.feature ? `<div class="feature">${esc(u.feature)}</div>` : ""}
      ${opt.extra || ""}
    </article>`;
  }

  // values: 값 목록, 또는 [값, 표시 글자] 목록
  function fillSelect(sel, values, label) {
    const cur = sel.value;
    const pairs = values.map((v) => (Array.isArray(v) ? v : [v, v]));
    sel.innerHTML = `<option value="">${label}</option>` +
      pairs.map(([v, t]) => `<option value="${esc(v)}">${esc(t)}</option>`).join("");
    if (pairs.some(([v]) => v === cur)) sel.value = cur;
  }

  // 여러 개 고르는 단지 선택 칸 (버튼 + 체크 목록). el._sel = 고른 단지 이름 Set (비면 전체)
  function multiSelect(el, names, label, onChange) {
    el._sel = new Set([...(el._sel || [])].filter((n) => names.includes(n)));
    const text = () => {
      const n = el._sel.size, first = names.find((x) => el._sel.has(x));
      return !n ? label : n === 1 ? first : `${first} 외 ${n - 1}곳`;
    };
    const wasOpen = el.querySelector(".msel-pop") && !el.querySelector(".msel-pop").hidden;
    el.innerHTML = `<button type="button" class="msel-btn${el._sel.size ? " on" : ""}" aria-haspopup="true">${esc(text())}</button>
      <div class="msel-pop"${wasOpen ? "" : " hidden"}>
        <label class="msel-all"><input type="checkbox" data-v=""${el._sel.size ? "" : " checked"}> ${esc(label)}</label>
        ${names.map((n) => `<label><input type="checkbox" data-v="${esc(n)}"${el._sel.has(n) ? " checked" : ""}> ${esc(n)}</label>`).join("")}
      </div>`;
    const pop = el.querySelector(".msel-pop");
    el.querySelector(".msel-btn").onclick = (e) => {
      e.stopPropagation();
      document.querySelectorAll(".msel-pop").forEach((p) => { if (p !== pop) p.hidden = true; });
      pop.hidden = !pop.hidden;
    };
    pop.onclick = (e) => e.stopPropagation();
    pop.querySelectorAll("input").forEach((cb) => {
      cb.onchange = () => {
        const v = cb.dataset.v;
        if (!v) el._sel.clear();
        else if (cb.checked) el._sel.add(v); else el._sel.delete(v);
        multiSelect(el, names, label, onChange);   // 목록은 열어 둔 채로 다시 그림
        onChange();
      };
    });
  }
  document.addEventListener("click", () => document.querySelectorAll(".msel-pop").forEach((p) => { p.hidden = true; }));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") document.querySelectorAll(".msel-pop").forEach((p) => { p.hidden = true; });
  });

  // 순위 기준에 맞는 점수로 바꾼 급매 목록 (점수 높은 순)
  const rankMode = () => (store.get(RANKMODE_STORE) === "supply" ? "supply" : "band");
  const rankScope = () => (store.get(RANKSCOPE_STORE) === "group" ? "group" : "complex");
  // 그룹 통합: 점수는 단지별 계산 그대로 두고, 가격 순위만 선택한 그룹(없으면 전체 단지) 전체에서 다시 센다.
  // 순위 모집단 = 그룹 안의 같은 거래·같은 평형 활성 매물 전체 (필터와 무관하게 고정)
  function groupRanks(list, mode) {
    const peers = {};
    (data.units || []).forEach((r) => {
      if (groupIds && !groupIds.has(r[0])) return;
      const k = r[1] + "|" + (mode === "band" ? r[2] : r[11]);
      (peers[k] = peers[k] || []).push(r[3]);
    });
    const rng = data.bandRanges || {};
    const scopeName = groupIds ? "그룹" : "전체 단지";
    return list.map((h) => {
      const ps = peers[h.trade + "|" + (mode === "band" ? h.band : h.supply)] || [h.price];
      const rank = ps.filter((p) => p < h.price).length + 1;   // 같은 가격은 같은 순위
      const cr = mode === "band" ? h.groupRank : h.groupRankS, cn = mode === "band" ? h.groupSize : h.groupSizeS;
      const label = mode === "band" ? (rng[h.band] || h.band) : `${h.supply}㎡`;
      const chip = `${label} ${scopeName} ${rank}위/${ps.length}` + (cr ? ` · 단지 ${cr}위/${cn}` : "");
      const rest = (h.reasons || []).filter((t) => !t.includes(" 중 낮은 가격 "));
      const at = rest[0] === "저층" ? 1 : 0;
      return { ...h, groupWideRank: rank, reasons: [...rest.slice(0, at), chip, ...rest.slice(at)] };
    });
  }
  function hotList() {
    const list = data.hot || [];
    const mode = rankMode();
    let out = list;
    if (mode === "supply" && list.some((h) => h.scoreS != null)) {
      out = list.map((h) => ({ ...h, score: h.scoreS ?? h.score, reasons: h.reasonsS || h.reasons }))
        .sort((a, b) => (b.score || 0) - (a.score || 0));
    }
    return rankScope() === "group" ? groupRanks(out, mode) : out;
  }

  function renderHot() {
    const mode = rankMode();
    document.querySelectorAll("#rankMode button").forEach((b) => {
      b.setAttribute("aria-checked", b.dataset.mode === mode);
      b.onclick = () => { store.set(RANKMODE_STORE, b.dataset.mode); renderLists(); };
    });
    const scope = rankScope();
    document.querySelectorAll("#rankScope button").forEach((b) => {
      b.setAttribute("aria-checked", b.dataset.scope === scope);
      if (b.dataset.scope === "group") b.textContent = groupIds ? "그룹 통합" : "전체 통합";
      b.onclick = () => { store.set(RANKSCOPE_STORE, b.dataset.scope); renderLists(); };
    });
    renderUnitTab(HOT_TAB);
    renderUnitTab(PRICE_TAB);
  }

  // 급매 탭과 가격 탭: 같은 매물 목록을 정렬만 달리해서 보여 준다
  const HOT_TAB = { c: "#fComplex", s: "#fSupply", o: "#fOurs", sort: "#hotSort", list: "#hotList", count: "#hotCount" };
  const PRICE_TAB = { c: "#pComplex", s: "#pSupply", o: "#pOurs", t: "#pTrade", sort: "#prSort", list: "#prList", count: "#prCount" };
  const TRADE_ORDER = { 매매: 0, 전세: 1, 월세: 2, 단기임대: 3 };
  const byPrice = (a, b) => (TRADE_ORDER[a.trade] ?? 9) - (TRADE_ORDER[b.trade] ?? 9) ||
    (a.price || 0) - (b.price || 0) || (a.rent || 0) - (b.rent || 0) || (b.score || 0) - (a.score || 0);
  const PAGE = 100;
  function renderUnitTab(T) {
    const all = hotList().filter(inGroup);
    // 단지 순서 = 마스터의 config/complexes.txt 순서 (complexOrder)
    const order = (data.complexOrder || []).map((c) => c.name);
    const present = new Set(all.map((h) => h.complex));
    const names = order.filter((n) => present.has(n)).concat([...present].filter((n) => !order.includes(n)));
    // 세부 평형: "112 (34평)" — 공급면적을 평으로 반올림
    const supplyPy = {};
    all.forEach((h) => { const v = h.py ?? (h.pyeong && Math.round(h.pyeong)); if (h.supply && v && !supplyPy[h.supply]) supplyPy[h.supply] = v; });
    const supplies = [...new Set(all.map((h) => String(h.supply)))]
      .sort((a, b) => parseFloat(a) - parseFloat(b) || a.localeCompare(b));
    fillSelect($(T.s), supplies.map((v) =>
      [v, supplyPy[v] ? `${v} (${supplyPy[v]}평)` : v]), "세부 평형 전체");
    let shown = PAGE;
    const apply = (keep) => {
      if (!keep) shown = PAGE;
      const cs = $(T.c)._sel || new Set(), s = $(T.s).value, o = $(T.o).value, t = T.t ? $(T.t).value : "";
      const rows = all.filter((h) => (!cs.size || cs.has(h.complex)) && (!s || String(h.supply) === s) &&
        (!t || h.trade === t || (t === "월세" && h.trade === "단기임대")) &&
        (!o || (o === "only" ? h.ours : !h.ours)));
      if ($(T.sort).value === "price") rows.sort(byPrice);   // 아니면 점수순 (hotList 순서)
      $(T.count).textContent = `매물 ${rows.length}건`;
      const more = rows.length > shown
        ? `<button type="button" class="more-btn">더 보기 (${rows.length - shown}건 남음)</button>` : "";
      $(T.list).innerHTML = (rows.slice(0, shown).map((h) => itemHtml(h, { score: true })).join("") ||
        `<p class="empty">조건에 맞는 매물이 없습니다.</p>`) + more;
      const m = $(T.list).querySelector(".more-btn");
      if (m) m.onclick = () => { shown += PAGE; apply(true); };
    };
    multiSelect($(T.c), names, "전체 단지", () => apply(false));
    [T.s, T.o, T.t, T.sort].filter(Boolean).forEach((id) => { $(id).onchange = () => apply(false); });
    apply(false);
  }

  function renderChanges() {
    const sec = (list, el, n, opt) => {
      $(n).textContent = list.length ? `${list.length}건` : "";
      $(el).innerHTML = list.map((u) => itemHtml(u, opt)).join("") || `<p class="empty">없습니다.</p>`;
    };
    const ok = (x) => inGroup(x) && (!chg || x.complexId === chg.id);
    $("#chgScope").hidden = !chg;
    if (chg) {
      $("#chgScope").innerHTML = `<span>${esc(chg.name)}만 보는 중</span><button type="button" id="chgAll">전체 단지 보기</button>`;
      $("#chgAll").onclick = () => { chg = null; renderChanges(); };
    }
    const rises = (data.rises || []).filter(ok);
    sec((data.drops || []).filter(ok), "#dropList", "#nDrop", { change: true });
    sec((data.new || []).filter(ok), "#newList", "#nNew", {});
    sec((data.gone || []).filter(ok), "#goneList", "#nGone", { gone: true });
    $("#riseWrap").hidden = !rises.length;
    if (rises.length) sec(rises, "#riseList", "#nRise", { change: true });
  }

  function renderMarket() {
    // 주간 흐름: 활성 매물 수(선) + 신규·사라짐(막대)
    const t = data.trends || [];
    if (t.length < 2) {
      $("#trend").innerHTML = `<p class="empty">주간 추이는 기록이 2주 이상 쌓이면 표시됩니다.</p>`;
    } else {
      const W = 640, H = 220, L = 44, R = 16, T = 16, B = 28;
      const x = (i) => L + (i + 0.5) * (W - L - R) / t.length;
      const amax = Math.max(...t.map((d) => d.active)) * 1.1 || 1;
      const bmax = Math.max(1, ...t.map((d) => Math.max(d.new, d.gone)));
      const ya = (v) => T + (H - T - B) * (1 - v / amax);
      const yb = (v) => (H - B) - (H - T - B) * 0.45 * (v / bmax);
      const bw = Math.max(3, (W - L - R) / t.length / 3.5);
      const css = getComputedStyle(document.documentElement);
      const c = (n) => css.getPropertyValue(n).trim();
      let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="주간 매물 흐름">`;
      for (let k = 0; k <= 4; k++) {
        const v = amax * k / 4, y = ya(v);
        s += `<line x1="${L}" x2="${W - R}" y1="${y}" y2="${y}" stroke="${c("--line")}"/>` +
          `<text x="${L - 6}" y="${y + 4}" font-size="11" text-anchor="end" fill="${c("--muted")}">${Math.round(v)}</text>`;
      }
      t.forEach((d, i) => {
        s += `<rect x="${x(i) - bw - 1}" y="${yb(d.new)}" width="${bw}" height="${H - B - yb(d.new)}" fill="${c("--good")}" opacity=".7"><title>${d.week} 신규 ${d.new}</title></rect>`;
        s += `<rect x="${x(i) + 1}" y="${yb(d.gone)}" width="${bw}" height="${H - B - yb(d.gone)}" fill="${c("--muted")}" opacity=".6"><title>${d.week} 사라짐 ${d.gone}</title></rect>`;
        if (i % Math.ceil(t.length / 8) === 0 || i === t.length - 1)
          s += `<text x="${x(i)}" y="${H - 8}" font-size="11" text-anchor="middle" fill="${c("--muted")}">${d.week.slice(5).replace("-", "/")}</text>`;
      });
      s += `<polyline fill="none" stroke="${c("--accent")}" stroke-width="2" points="${t.map((d, i) => `${x(i)},${ya(d.active)}`).join(" ")}"/>`;
      t.forEach((d, i) => { s += `<circle cx="${x(i)}" cy="${ya(d.active)}" r="3" fill="${c("--accent")}"><title>${d.week} 활성 ${d.active}</title></circle>`; });
      s += `</svg><div class="legend"><span><i style="background:${c("--accent")}"></i>활성 매물(주말 기준)</span>` +
        `<span><i style="background:${c("--good")}"></i>신규</span><span><i style="background:${c("--muted")}"></i>사라짐</span></div>`;
      $("#trend").innerHTML = s;
    }
    // 기준선 표
    const mode = store.get(BASEMODE_STORE) === "band" ? "band" : "supply";
    document.querySelectorAll("#baseMode button").forEach((b) => {
      b.setAttribute("aria-checked", b.dataset.mode === mode);
      b.onclick = () => { store.set(BASEMODE_STORE, b.dataset.mode); renderMarket(); };
    });
    const rows = ((mode === "band" ? data.baselinesByBand : data.baselines) || []).filter((b) => inGroupOnly(b) && passBase(b));
    $("#baseNote").hidden = !(F.pmin != null || F.pmax != null || F.rmin != null || F.rmax != null || attrOn());
    let html = `<thead><tr><th>${mode === "band" ? "대표 평형" : "평형"}</th><th>거래</th><th>활성</th><th>최저 호가</th><th>호가 중앙값</th><th>기준선</th><th>거래권</th><th>거래권 매물</th></tr></thead><tbody>`;
    let last = null;
    rows.forEach((r) => {
      if (r.complex !== last) { html += `<tr class="group"><td colspan="8">${esc(r.complex)}</td></tr>`; last = r.complex; }
      const label = mode === "band"
        ? `${esc(r.band)} <span class="muted">${esc((r.supplies || []).join("·"))}</span>`
        : `${esc(r.supply)}㎡ <span class="muted">${esc(r.band || "")}</span>`;
      html += `<tr><td>${label}</td><td>${esc(r.trade)}</td><td>${r.active}</td><td>${esc(r.minText)}</td>` +
        `<td>${esc(r.medianText)}</td><td>${esc(r.baselineText) || "-"}${r.baselineN ? ` <span class="muted">(${r.baselineN}건)</span>` : ""}</td>` +
        `<td>${esc(r.zoneText) || "-"}</td><td>${r.inZone || ""}</td></tr>`;
    });
    $("#baseTable").innerHTML = rows.length ? html + "</tbody>" : `<tbody><tr><td class="empty">이 조건의 매물이 없습니다.</td></tr></tbody>`;
  }

  load();
})();
