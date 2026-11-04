// sideroute: sends the window's PID to the sideroute D-Bus service, which moves the whole app
// into the tunnel (or back) without restarting it. KWin's callDBus sends numbers as int32.
function toggle(window) {
    if (!window || !window.pid) return;
    callDBus("io.github.attaberuku.Sideroute", "/io/github/attaberuku/Sideroute",
             "io.github.attaberuku.Sideroute", "Toggle", window.pid);
}

registerUserActionsMenu(function (window) {
    return {
        text: "Route through Sideroute (on / off)",
        icon: "network-vpn",
        triggered: function () { toggle(window); }
    };
});

registerShortcut("SiderouteToggle", "Sideroute: move the active window's app into the tunnel / back",
                 "Meta+Alt+V", function () { toggle(workspace.activeWindow); });
