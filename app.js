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
  const RANKSCOPE_STORE = "nlb.rankscope";  // 순위 범위: complex(단지별, 기본) / group(선택한 그룹 통합)   // 급매 점수의 가격 비교 묶음: band(대표 평형, 기본) / supply(세부 평형)
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
  const TAGS = ["올수리", "복층", "급매", "세안고"];
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
    $("#asof").textContent = `데이터 기준 ${m.dataDate} · 생성 ${m.generatedAt.slice(0, 16).replace("T", " ")} · 단지 ${m.complexes}곳`;
    const ageH = (Date.now() - Date.parse(m.generatedAt)) / 36e5;
    const warns = [];
    if (ageH > STALE_HOURS) warns.push(`데이터가 ${Math.floor(ageH)}시간 전 것입니다. 마스터 PC 수집을 확인하세요.`);
    if (m.failed && m.failed.length) warns.push(`수집이 불완전한 단지: ${m.failed.join(", ")}`);
    $("#warn").hidden = !warns.length;
    $("#warn").textContent = warns.join(" ");
    setupGroups();
    setupFilter();
    renderLists();
  }

  function renderLists() {
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
    const resetLocal = () => { ["#fComplex", "#fSupply", "#pComplex", "#pSupply"].forEach((id) => { $(id).value = ""; }); };
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
        if (!changed && ["#fComplex", "#fSupply", "#pComplex", "#pSupply"].some((id) => $(id).value)) { resetLocal(); renderLists(); }
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
    $("#summary").innerHTML = (cards.map((s) => `
      <div class="card${s.scannedToday && s.complete ? "" : " stale"}">
        <h3>${esc(s.complex)}</h3>
        <div class="big">${s.active}<span class="muted small"> 건</span></div>
        <div class="muted small">매매 ${s.sale} · 전세 ${s.jeonse} · 월세 ${s.monthly}</div>
        <div class="row">
          <span class="tag-new">신규 ${s.new}</span>
          <span class="tag-drop">인하 ${s.drop}</span>
          <span class="tag-gone">사라짐 ${s.gone}</span>
        </div>
      </div>`).join("")) || `<p class="empty">이 조건의 매물이 없습니다.</p>`;
  }

  // 거래방식 배지 · 가격 색 (매매=흰 배경, 전세=주황, 월세=초록, 단기임대=보라)
  const TRADE_CLASS = { "매매": "sale", "전세": "jeonse", "월세": "monthly", "단기임대": "short" };
  const tradeBadge = (t) => t ? `<span class="tb tb-${TRADE_CLASS[t] || "sale"}">${esc(t)}</span>` : "";

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
      <div class="title">${tradeBadge(u.trade)}${esc(u.complex)}${ours}</div>
      <div class="price pr-${tcls}">${price}</div>
      <div class="meta">${esc(meta)}</div>
      ${reasons ? `<div class="reasons">${reasons}</div>` : ""}
      ${u.feature ? `<div class="feature">${esc(u.feature)}</div>` : ""}
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
  const PRICE_TAB = { c: "#pComplex", s: "#pSupply", o: "#pOurs", sort: "#prSort", list: "#prList", count: "#prCount" };
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
    fillSelect($(T.c), names, "전체 단지");
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
      const c = $(T.c).value, s = $(T.s).value, o = $(T.o).value;
      const rows = all.filter((h) => (!c || h.complex === c) && (!s || String(h.supply) === s) &&
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
    [T.c, T.s, T.o, T.sort].forEach((id) => { $(id).onchange = () => apply(false); });
    apply(false);
  }

  function renderChanges() {
    const sec = (list, el, n, opt) => {
      $(n).textContent = list.length ? `${list.length}건` : "";
      $(el).innerHTML = list.map((u) => itemHtml(u, opt)).join("") || `<p class="empty">없습니다.</p>`;
    };
    const rises = (data.rises || []).filter(inGroup);
    sec((data.drops || []).filter(inGroup), "#dropList", "#nDrop", { change: true });
    sec((data.new || []).filter(inGroup), "#newList", "#nNew", {});
    sec((data.gone || []).filter(inGroup), "#goneList", "#nGone", { gone: true });
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
