$(document).ready(function () {
    var devicetable = $('#dataTable').DataTable({});

    var capfiles_display = document.getElementById("capfiles");

    // table
    eel.expose(add_to_table);

    var sn = 0

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
    }

    eel.expose(update_capfiles);

    function update_capfiles(number) {
        capfiles_display.innerHTML = "<big><big>" + number + "</big></big>";
    }
});