$(document).ready(function () {
    var devicetable = $('#dataTable').DataTable({});

    var capfiles_display = document.getElementById("capfiles");
    var capfiles_display2 = document.getElementById("capfiles2");
    var capfiles_displaybig = document.getElementById("file_display");

    capfiles_display.innerHTML = "<big><big>" + 0 + "</big></big>";
    capfiles_display2.innerHTML = 0;
    capfiles_displaybig.innerHTML = 0;

    var https_display = document.getElementById("https_display");
    var http_display = document.getElementById("http_display");
    var other_display = document.getElementById("other_display");

    https_display.innerHTML = 0;
    http_display.innerHTML = 0;
    other_display.innerHTML = 0;

    // table
    eel.expose(add_to_table);

    var sn = 0;
    var http_count = 0;
    var https_count = 0;
    var other_count = 0;

    function add_to_table(alert, tx, rx, packet) {
        var alert_add = "<small>" + alert + "</small>"
        var tx_add = "<small>" + tx + "</small>"
        var rx_add = "<small>" + rx + "</small>"
        var packet_add = "<span style='font-size:0.7em;width:400px;display:block;word-wrap:break-word;'>" + packet + "</span>"
        console.log("Populating table...")
        devicetable.row.add([
            sn,
            alert_add,
            tx_add,
            rx_add,
            packet_add,
        ]).draw(false);
        sn += 1;

        if (alert.indexOf("443") >= 0) {
            https_count += 1;
            https_display.innerHTML = "<b>"+https_count+"</b>";
        } else if (alert.indexOf("80") >= 0) {
            http_count += 1;
            http_display.innerHTML = "<b>"+http_count+"</b>";
        } else {
            other_count += 1;
            other_display.innerHTML = "<b>"+other_count+"</b>";
        }
    }

    eel.expose(update_capfiles);

    function update_capfiles(number) {
        capfiles_display.innerHTML = "<big><big>" + number + "</big></big>";
        capfiles_display2.innerHTML = number;
        capfiles_displaybig.innerHTML = "<b>"+number+"</b>";
    }
});