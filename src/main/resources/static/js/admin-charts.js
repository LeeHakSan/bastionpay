/* 보안 대시보드 그래프. Chart.js(js/vendor/chart.umd.js)로 /admin/security/charts 의 JSON 을 그린다.
   CSP(script-src 'self') 때문에 인라인 스크립트 없이 이 파일 하나에서 모두 처리한다.
   - 개요: 그래프 4개. 마우스를 올리면 그 요소가 살짝 올라오고 나머지는 흐려지며, 누르면 그 그래프의 상세 화면으로 간다.
   - 상세(data-mode="detail"): 그래프 하나를 크게. 막대·조각을 누르면 같은 화면이 그 조건으로 다시 열려 아래 목록이 걸러진다. */
(function () {
  'use strict';

  var root = document.querySelector('[data-charts]');
  if (!root) return;

  var errorBox = document.getElementById('chart-error');
  function fail() { if (errorBox) errorBox.hidden = false; }
  if (typeof Chart === 'undefined') { fail(); return; }

  var detail = root.getAttribute('data-mode') === 'detail';
  // 상세 화면에서 이미 고른 조건(없으면 null)
  var sel = {
    from: root.getAttribute('data-sel-from'),
    series: root.getAttribute('data-sel-series'),
    type: root.getAttribute('data-sel-type'),
    ip: root.getAttribute('data-sel-ip')
  };

  // 색: 사이트 토큰을 읽고, 심각도 색은 대시보드 태그(.tag--*)와 같은 계열로 맞춘다
  var css = getComputedStyle(document.documentElement);
  function token(name, fallback) { return (css.getPropertyValue(name) || '').trim() || fallback; }
  var INK = token('--ink', '#0b2140');
  var INK2 = token('--ink-2', '#435570');
  var LINE = token('--line', '#dde3ec');
  var NAVY = token('--navy-900', '#0b2140');
  var FONT = token('--font', 'sans-serif');

  var SEVERITY = { INFO: '#c9d6ea', LOW: '#7f9cc7', MEDIUM: '#e0b85c', HIGH: '#c4393f', CRITICAL: '#6e1117' };
  var TRANSFER = { COMPLETED: '#12305a', FAILED: '#e0b85c', REFUNDED: '#7f9cc7', REVIEW: '#a4262c' };
  var SLICES = ['#0b2140', '#27456f', '#4a6fa5', '#7f9cc7', '#a5bbdd', '#c9d6ea', '#dde3ec'];

  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  Chart.defaults.font.family = FONT;
  Chart.defaults.font.size = detail ? 13 : 12;
  Chart.defaults.color = INK2;
  // 기본 설정(easing 등)을 지우지 않도록 값만 바꾼다. 통째로 덮어쓰면 전환이 중간에 멈춘다
  if (reduceMotion) {
    Chart.defaults.animation = false;
  } else {
    Chart.defaults.animation.duration = 450;
  }
  // 호버는 즉시 바뀐다: 올린 요소의 색 전환과 툴팁 이동·크기 애니메이션을 끈다(빠르게 움직일 때 툴팁 상자가 어긋나 보이는 것을 막는다)
  Chart.defaults.transitions.active.animation.duration = 0;
  Chart.defaults.plugins.tooltip.animation = false;
  Chart.defaults.plugins.tooltip.backgroundColor = NAVY;
  Chart.defaults.plugins.tooltip.titleFont = { family: FONT, weight: '700' };
  Chart.defaults.plugins.tooltip.footerFont = { family: FONT, weight: '400', size: 12 };
  Chart.defaults.plugins.tooltip.footerColor = '#c9d6ea';
  Chart.defaults.plugins.tooltip.cornerRadius = 2;
  Chart.defaults.plugins.tooltip.padding = 10;

  var HINT = detail ? '눌러서 아래 목록 보기' : '눌러서 크게 보기';

  function number(n) { return Number(n).toLocaleString('ko-KR'); }
  function sum(list) { return list.reduce(function (a, b) { return a + b; }, 0); }
  function text(id, value) { var el = document.getElementById(id); if (el) el.textContent = value; }

  function fade(hex, alpha) {
    var h = hex.replace('#', '');
    if (h.length === 3) h = h.replace(/(.)/g, '$1$1');
    var n = parseInt(h, 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + alpha + ')';
  }

  /* 호버·선택 강조. 차트를 다시 계산(update)하지 않고, 요소 위에 덧그리는 것만 부드럽게 바꾼다.
     - 올린 막대·조각: 살짝 커지면서 그림자가 생긴다(lift)
     - 나머지: 흰색 막이 덮여 흐려진다(dim)
     - 상세 화면에서 고른 요소가 있으면 마우스를 올리지 않아도 나머지는 흐리게 둔다
     값은 목표를 향해 부드럽게 따라가는 방식(지수 감쇠)이라 마우스를 빠르게 움직여도 끊기거나 튀지 않는다.
     picked({datasetIndex, dataIndex}) 는 상세 화면에서 이미 고른 요소인지 알려 주는 함수(없으면 null). */
  var DIM = 0.66;          // 흐린 요소 위에 덮는 흰색의 최대 진하기
  var DIM_SPEED = 70;      // 흐려지는 속도(ms, 작을수록 빠름)
  var LIFT_SPEED = 55;     // 올라오는 속도(ms)
  var LEAVE_DELAY = 90;    // 막대 사이 빈틈을 지날 때 강조가 깜빡이지 않도록 기다리는 시간(ms)

  function baseColor(chart, di, i) {
    var bg = chart.data.datasets[di].backgroundColor;
    return Array.isArray(bg) ? bg[i % bg.length] : bg;
  }

  function emphasis(picked) {
    return {
      id: 'emphasis',
      // 보여 줄 항목이 없는 툴팁(데이터가 없는 시간 구간)은 아예 그리지 않는다
      beforeTooltipDraw: function (chart, args) {
        return args.tooltip.dataPoints && args.tooltip.dataPoints.length > 0 ? undefined : false;
      },
      afterDatasetsDraw: function (chart) {
        var dim = chart.$dim || 0, lift = chart.$lift || 0, lifted = chart.$liftEl;
        // 마우스를 막 벗어나 흐림이 사라지는 동안에는 마지막으로 올렸던 요소를 기준으로 계속 그린다(고른 요소가 있으면 그쪽이 기준)
        var hover = chart.$hover || (picked ? null : lifted);
        if (dim < 0.01 && lift < 0.01) return;
        var ctx = chart.ctx;
        ctx.save();
        // 1) 나머지 요소를 흐리게
        if (dim >= 0.01) {
          ctx.fillStyle = 'rgba(255,255,255,' + (DIM * dim).toFixed(3) + ')';
          chart.data.datasets.forEach(function (dataset, di) {
            var meta = chart.getDatasetMeta(di);
            if (meta.hidden) return;
            meta.data.forEach(function (el, i) {
              var focused = hover ? (hover.datasetIndex === di && hover.index === i) : (picked ? picked({ datasetIndex: di, dataIndex: i }) : true);
              if (!focused) shape(chart, ctx, el, 0);
            });
          });
        }
        // 2) 올린 요소를 살짝 키우고 그림자를 준다
        if (lift >= 0.01 && lifted) {
          var el = chart.getDatasetMeta(lifted.datasetIndex).data[lifted.index];
          if (el) {
            ctx.shadowColor = 'rgba(11,33,64,' + (0.32 * lift).toFixed(3) + ')';
            ctx.shadowBlur = 12 * lift;
            ctx.shadowOffsetY = 3 * lift;
            ctx.fillStyle = baseColor(chart, lifted.datasetIndex, lifted.index);
            shape(chart, ctx, el, lift);
          }
        }
        ctx.restore();
      }
    };
  }

  // 요소(막대·도넛 조각) 모양 그대로 채운다. grow 가 0보다 크면 그만큼 바깥으로 키운다(0~1)
  function shape(chart, ctx, el, grow) {
    if (chart.config.type === 'doughnut') {
      var a = el.getProps(['x', 'y', 'startAngle', 'endAngle', 'innerRadius', 'outerRadius'], true);
      ctx.beginPath();
      ctx.arc(a.x, a.y, a.outerRadius + 8 * grow, a.startAngle, a.endAngle);
      ctx.arc(a.x, a.y, a.innerRadius, a.endAngle, a.startAngle, true);
      ctx.closePath();
      ctx.fill();
      return;
    }
    var b = el.getProps(['x', 'y', 'base', 'width', 'height'], true), g = 2.5 * grow;
    if (chart.options.indexAxis === 'y') ctx.fillRect(Math.min(b.x, b.base) - 0, b.y - b.height / 2 - g, Math.abs(b.x - b.base) + g, b.height + 2 * g);
    else ctx.fillRect(b.x - b.width / 2 - g, Math.min(b.y, b.base) - g, b.width + 2 * g, Math.abs(b.y - b.base) + g);
  }

  // 목표값(dim, lift)을 향해 매 프레임 조금씩 다가간다. 도착하면 멈춘다
  function run(chart) {
    if (chart.$running) return;
    chart.$running = true;
    var last = performance.now();
    (function step(now) {
      var dt = Math.min(64, now - last); last = now;
      chart.$dim += (chart.$dimTo - chart.$dim) * (1 - Math.exp(-dt / DIM_SPEED));
      chart.$lift += (chart.$liftTo - chart.$lift) * (1 - Math.exp(-dt / LIFT_SPEED));
      var done = Math.abs(chart.$dimTo - chart.$dim) < 0.01 && Math.abs(chart.$liftTo - chart.$lift) < 0.01;
      if (done) { chart.$dim = chart.$dimTo; chart.$lift = chart.$liftTo; }
      chart.draw();
      if (done) { chart.$running = false; return; }
      requestAnimationFrame(step);
    })(last);
  }

  function set(chart, dimTo, liftTo) {
    chart.$dimTo = dimTo; chart.$liftTo = liftTo;
    if (reduceMotion) { chart.$dim = dimTo; chart.$lift = liftTo; chart.draw(); } else run(chart);
  }

  // 올린 요소가 바뀌면 새 요소가 처음부터 올라오게 하고, 요소가 없어지면 잠깐 기다렸다가 풀어 준다
  function focusOn(chart, hit, hasPicked) {
    function keyOf(h) { return h ? h.datasetIndex + ':' + h.index : ''; }
    if (hit) {
      if (chart.$leave) { clearTimeout(chart.$leave); chart.$leave = 0; }
      if (keyOf(hit) === keyOf(chart.$hover)) return;
      chart.$hover = hit;
      chart.$liftEl = hit;
      chart.$lift = reduceMotion ? 1 : 0.15;   // 새 요소는 거의 처음부터 올라온다(흐림은 그대로 이어진다)
      set(chart, 1, 1);
      return;
    }
    if (!chart.$hover || chart.$leave) return;
    chart.$leave = setTimeout(function () {
      chart.$leave = 0;
      chart.$hover = null;
      set(chart, hasPicked ? 1 : 0, 0);
    }, LEAVE_DELAY);
  }

  // 마우스를 올렸을 때 커서: 개요는 그래프 어디든 눌러서 갈 수 있고, 상세는 막대·조각 위에서만 누를 수 있다
  function hoverHandler(hasPicked) {
    return function (evt, elements, chart) {
      chart.canvas.style.cursor = (elements.length || !detail) ? 'pointer' : 'default';
      focusOn(chart, elements.length ? { datasetIndex: elements[0].datasetIndex, index: elements[0].index } : null, hasPicked);
    };
  }

  function wire(chart, hasPicked) {
    chart.$dim = chart.$dimTo = hasPicked ? 1 : 0;   // 상세 화면에서 이미 고른 요소가 있으면 처음부터 강조
    chart.$lift = chart.$liftTo = 0;
    chart.canvas.addEventListener('mouseleave', function () {
      if (chart.$leave) { clearTimeout(chart.$leave); chart.$leave = 0; }
      chart.$hover = null;
      set(chart, hasPicked ? 1 : 0, 0);
    });
    return chart;
  }

  // 누르기: 개요는 상세 화면으로(막대·조각을 눌렀으면 그 조건까지), 상세는 같은 화면에 조건을 붙여 다시 연다
  function goTo(chart, evt, paramsFor) {
    var hit = chart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, true)[0];
    var params = hit ? paramsFor(hit) : [];
    var base = detail ? root.getAttribute('data-detail') : chart.canvas.parentNode.getAttribute('data-detail');
    if (!base || (detail && !params.length)) return;
    window.location.href = base + (params.length ? (base.indexOf('?') < 0 ? '?' : '&') + params.join('&') : '');
  }

  // 데이터가 없으면 그래프 대신 안내 문구를 보인다
  function empty(canvasId, message) {
    var canvas = document.getElementById(canvasId);
    if (!canvas) return;
    var p = document.createElement('p');
    p.className = 'chart__empty';
    p.textContent = message;
    canvas.parentNode.replaceChild(p, canvas);
  }

  function describe(canvasId, label) {
    var canvas = document.getElementById(canvasId);
    if (canvas) canvas.setAttribute('aria-label', label);
  }

  // 이벤트 추이·이체 결과: 시간 구간별로 계열을 쌓은 막대
  function stacked(canvasId, series, colors, zeroMessage) {
    var canvas = document.getElementById(canvasId);
    if (!canvas) return 0;
    var total = series.datasets.reduce(function (a, d) { return a + sum(d.data); }, 0);
    if (total === 0) { empty(canvasId, zeroMessage); return total; }
    var picked = (detail && (sel.from || sel.series)) ? function (el) {
      return (!sel.from || String(series.starts[el.dataIndex]) === sel.from) && (!sel.series || series.datasets[el.datasetIndex].key === sel.series);
    } : null;
    wire(new Chart(canvas, {
      type: 'bar',
      data: {
        labels: series.labels,
        datasets: series.datasets.map(function (d) {
          return { label: d.label, data: d.data, backgroundColor: colors[d.key] || INK2, hoverBackgroundColor: colors[d.key] || INK2, borderWidth: 0, barPercentage: 0.82, categoryPercentage: 0.92 };
        })
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'nearest', intersect: true },   // 강조는 올린 막대 조각 하나
        onHover: hoverHandler(!!picked),
        onClick: function (evt, els, chart) {
          goTo(chart, evt, function (hit) { return ['from=' + series.starts[hit.index], 'series=' + encodeURIComponent(series.datasets[hit.datasetIndex].key)]; });
        },
        scales: {
          x: { stacked: true, grid: { display: false }, border: { color: LINE }, ticks: { maxTicksLimit: detail ? 24 : 12, maxRotation: 0 } },
          y: { stacked: true, beginAtZero: true, border: { display: false }, grid: { color: LINE }, ticks: { precision: 0, maxTicksLimit: 5 } }
        },
        plugins: {
          legend: {
            position: 'top', align: 'start', labels: { boxWidth: 10, boxHeight: 10, padding: 14, color: INK },
            onClick: detail ? undefined : function () {}   // 개요에서는 범례를 눌러도 감추지 않는다(눌러서 상세로 간다)
          },
          tooltip: {
            mode: 'index', intersect: false,   // 설명은 그 시간대의 모든 계열을 보여 준다
            filter: function (item) { return item.raw > 0; },
            callbacks: {
              // 값이 있는 계열이 하나도 없는 시간 구간(빈 막대 자리)에서는 items 가 비어 있다. 그때 오류가 나면 툴팁이 반쯤 그려진 채 남는다
              title: function (items) { return items.length ? series.titles[items[0].dataIndex] : ''; },
              footer: function (items) { return ['합계 ' + number(sum(items.map(function (i) { return i.raw; }))) + '건', HINT]; }
            }
          }
        }
      },
      plugins: [emphasis(picked)]
    }), !!picked);
    return total;
  }

  // 이벤트 종류별 비율: 도넛 + 가운데 합계
  function types(data) {
    var canvas = document.getElementById('chart-types');
    if (!canvas) return;
    if (!data.types.length) { empty('chart-types', '이 기간에는 기록된 이벤트가 없습니다.'); return; }
    var narrow = canvas.parentNode.clientWidth < 460;
    var picked = (detail && sel.type) ? function (el) { return data.types[el.dataIndex].key === sel.type; } : null;
    var center = {
      id: 'centerTotal',
      afterDraw: function (chart) {
        var area = chart.chartArea, ctx = chart.ctx;
        var x = (area.left + area.right) / 2, y = (area.top + area.bottom) / 2;
        ctx.save();
        ctx.textAlign = 'center';
        ctx.fillStyle = INK;
        ctx.font = '800 ' + (detail ? 28 : 22) + 'px ' + FONT;
        ctx.fillText(number(data.typesTotal), x, y + 4);
        ctx.fillStyle = INK2;
        ctx.font = (detail ? 13 : 12) + 'px ' + FONT;
        ctx.fillText('건', x, y + (detail ? 26 : 22));
        ctx.restore();
      }
    };
    wire(new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: data.types.map(function (s) { return s.key === 'OTHER' ? '기타' : s.key; }),
        datasets: [{
          data: data.types.map(function (s) { return s.count; }),
          backgroundColor: SLICES, hoverBackgroundColor: SLICES,
          borderColor: '#ffffff', borderWidth: 2, hoverOffset: 0, hoverBorderColor: '#ffffff'   // 튀어나오는 효과는 emphasis 가 부드럽게 그린다   // 올린 조각이 살짝 튀어나온다
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '66%',
        layout: { padding: 10 },
        onHover: hoverHandler(!!picked),
        onClick: function (evt, els, chart) { goTo(chart, evt, function (hit) { return ['type=' + encodeURIComponent(data.types[hit.index].key)]; }); },
        plugins: {
          legend: {
            position: narrow ? 'bottom' : 'right', labels: { boxWidth: 10, boxHeight: 10, padding: 10, color: INK },
            onClick: function () {}   // 범례는 누르지 않는다(조각을 눌러서 고른다)
          },
          tooltip: {
            callbacks: {
              label: function (item) {
                var pct = data.typesTotal ? Math.round(item.raw * 100 / data.typesTotal) : 0;
                return item.label + ' ' + number(item.raw) + '건 (' + pct + '%)';
              },
              footer: function () { return HINT; }
            }
          }
        }
      },
      plugins: [center, emphasis(picked)]
    }), !!picked);
    text('count-types', '최근 ' + data.rangeLabel + ' · ' + number(data.typesTotal) + '건');
    describe('chart-types', '이벤트 종류별 비율: ' + data.types.map(function (s) { return (s.key === 'OTHER' ? '기타' : s.key) + ' ' + number(s.count) + '건'; }).join(', '));
  }

  // 로그인 실패가 많은 IP: 가로 막대, 막대 끝에 건수
  function ips(data) {
    var canvas = document.getElementById('chart-ips');
    if (!canvas) return;
    if (!data.failedLoginIps.length) { empty('chart-ips', '이 기간에는 로그인 실패가 없습니다.'); return; }
    var picked = (detail && sel.ip) ? function (el) { return data.failedLoginIps[el.dataIndex].label === sel.ip; } : null;
    var values = {
      id: 'barValues',
      afterDatasetsDraw: function (chart) {
        var ctx = chart.ctx;
        ctx.save();
        ctx.fillStyle = INK;
        ctx.font = '700 ' + (detail ? 13 : 12) + 'px ' + FONT;
        ctx.textBaseline = 'middle';
        chart.getDatasetMeta(0).data.forEach(function (bar, i) {
          ctx.fillText(number(chart.data.datasets[0].data[i]), bar.x + 6, bar.y);
        });
        ctx.restore();
      }
    };
    wire(new Chart(canvas, {
      type: 'bar',
      data: {
        labels: data.failedLoginIps.map(function (b) { return b.label; }),
        datasets: [{
          label: '로그인 실패', data: data.failedLoginIps.map(function (b) { return b.count; }),
          backgroundColor: NAVY, hoverBackgroundColor: NAVY, borderWidth: 0, barPercentage: 0.7
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'nearest', intersect: true },
        onHover: hoverHandler(!!picked),
        onClick: function (evt, els, chart) { goTo(chart, evt, function (hit) { return ['ip=' + encodeURIComponent(data.failedLoginIps[hit.index].label)]; }); },
        layout: { padding: { right: 36 } },
        scales: {
          x: { beginAtZero: true, border: { display: false }, grid: { color: LINE }, ticks: { precision: 0, maxTicksLimit: 5 } },
          y: { grid: { display: false }, border: { color: LINE }, ticks: { color: INK, font: { family: FONT, size: detail ? 13 : 12 } } }
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: function (item) { return number(item.raw) + '회 실패'; }, footer: function () { return HINT; } } }
        }
      },
      plugins: [values, emphasis(picked)]
    }), !!picked);
    describe('chart-ips', '로그인 실패가 많은 IP: ' + data.failedLoginIps.map(function (b) { return b.label + ' ' + number(b.count) + '회'; }).join(', '));
  }

  // 글꼴(Pretendard)이 준비된 뒤에 그린다. 준비 전에 글자 폭을 재면 범례가 잘린다
  var fontsReady = document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve();
  fontsReady
    .then(function () { return fetch(root.getAttribute('data-src'), { credentials: 'same-origin', headers: { Accept: 'application/json' } }); })
    .then(function (res) {
      var type = res.headers.get('content-type') || '';
      if (!res.ok || type.indexOf('json') < 0) throw new Error('chart data ' + res.status);
      return res.json();
    })
    .then(function (data) {
      var all = stacked('chart-timeline', data.timeline, SEVERITY, '이 기간에는 기록된 이벤트가 없습니다.');
      text('count-timeline', '최근 ' + data.rangeLabel + ' · 총 ' + number(all) + '건' + (detail ? '' : ' · 심각도별'));
      describe('chart-timeline', '시간대별 보안 이벤트 ' + number(all) + '건을 심각도별로 쌓은 막대 그래프');
      var moved = stacked('chart-transfers', data.transfers, TRANSFER, '이 기간에는 이체 기록이 없습니다.');
      text('count-transfers', '최근 ' + data.rangeLabel + (moved ? ' · ' + number(moved) + '건' : ''));
      describe('chart-transfers', '시간대별 이체 결과 ' + number(moved) + '건 막대 그래프');
      types(data);
      ips(data);
    })
    .catch(fail);
})();
