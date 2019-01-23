$(document).ready(function() {

    var table_container = $('#dataTable');
    if (table_container.length > 0) {
        var table = table_container.DataTable({
            data: dataTable,
            columns: [
                { title: "Mes" },
                { title: "Total Ventas" }
            ]
        });

        $("#dataTable tbody").on('click', 'tr', function () {
            var data = table.row(this).data();
            window.location.href = "/formulario/"+data[0];
        }).on('mouseover', 'tr', function () {
            $('html,body').css('cursor','pointer');
        }).on('mouseout','tr',function () {
            $('html,body').css('cursor','auto');
        });
    }


});



$(document).ready(function() {
	$(chart_id).highcharts({
		chart: chart,
		title: title,
		xAxis: xAxis,
		yAxis: yAxis,
		series: series
	});
});


