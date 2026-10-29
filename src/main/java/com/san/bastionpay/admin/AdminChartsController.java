package com.san.bastionpay.admin;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 보안 대시보드 그래프 데이터(JSON). 관리자만 읽을 수 있고, 화면의 스크립트가 불러 그린다. */
@RestController
@RequestMapping("/admin/security/charts")
@PreAuthorize("hasRole('ADMIN')")
public class AdminChartsController {

    private final SecurityChartService charts;

    public AdminChartsController(SecurityChartService charts) {
        this.charts = charts;
    }

    @GetMapping
    public SecurityChartService.ChartData data(@RequestParam(defaultValue = "24h") String range) {
        return charts.load(SecurityDashboardService.Range.of(range));
    }
}
