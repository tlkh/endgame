$(document).ready(function () {
    var devicetable = $('#dataTable').DataTable({});

    /*
    // main displays
    var devices_total_display = document.getElementById("devices-total-display");
    var devices_ssh_display = document.getElementById("devices-ssh-display");
    var devices_vnc_display = document.getElementById("devices-vnc-display");
    var devices_weak_display = document.getElementById("devices-weak-display");

    var ssh_count = 0;
    var vnc_count = 0;
    var others_count = 0;
    var total_count = 0;
    var weak_count = 0;

    function update_counts() {
        devices_ssh_display.innerHTML = ssh_count;
        devices_vnc_display.innerHTML = vnc_count;
        devices_weak_display.innerHTML = weak_count;
        devices_total_display.innerHTML = total_count;
    }

    update_counts();*/

    // table
    eel.expose(add_to_table);

    function add_to_table(alert, tx, rx, packet) {
        console.log("Populating table...")
        devicetable.row.add([
            alert,
            tx,
            rx,
            packet
        ]).draw(false);
        console.log("splitting ports");
    }
});