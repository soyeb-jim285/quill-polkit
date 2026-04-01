pragma ComponentBehavior: Bound

import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import QtQuick
import QtQuick.Layouts
import "../quill" as Quill
import "../icons"

Scope {
    id: root

    property bool visible: false
    property string cookie: ""
    property string message: ""
    property string userName: ""
    property string actionId: ""
    property string password: ""
    property string errorMsg: ""
    property string status: "idle" // idle, input, verifying, error, success
    property int uid: parseInt(Quickshell.env("UID") || "1000")

    readonly property string socketPath: "/run/user/" + root.uid + "/quill-polkit.sock"

    function show(data: var): void {
        root.cookie = data.cookie || "";
        root.message = data.message || "";
        root.userName = data.user || "";
        root.actionId = data.actionId || "";
        root.password = "";
        root.errorMsg = "";
        root.status = "input";
        root.visible = true;
    }

    function dismiss(): void {
        root.visible = false;
        root.status = "idle";
        root.password = "";
        root.errorMsg = "";
        root.cookie = "";
    }

    function sendToAgent(data: var): void {
        let escaped = JSON.stringify(data).replace(/'/g, "'\\''");
        sendProc.command = ["bash", "-c",
            "printf '%s\\n' '" + escaped + "' | python3 -c \"import socket,sys,os; s=socket.socket(socket.AF_UNIX); s.connect('" + root.socketPath + "'); s.send(sys.stdin.buffer.readline()); s.close()\""
        ];
        sendProc.running = true;
    }

    function submitPassword(): void {
        if (root.password.length === 0) return;
        root.status = "verifying";
        root.sendToAgent({
            cookie: root.cookie,
            type: "password",
            password: root.password
        });
    }

    function cancelAuth(): void {
        root.sendToAgent({
            cookie: root.cookie,
            type: "cancel"
        });
        root.dismiss();
    }

    Process {
        id: sendProc
        command: ["true"]
        running: false
    }

    IpcHandler {
        target: "polkit"

        function beginAuth(data: string): void {
            let parsed = JSON.parse(data);
            root.show(parsed);
        }

        function cancelAuth(data: string): void {
            let parsed = JSON.parse(data);
            if (parsed.cookie === root.cookie) {
                root.dismiss();
            }
        }

        function authFailed(data: string): void {
            let parsed = JSON.parse(data);
            if (parsed.cookie !== root.cookie) return;

            if (parsed.fatal) {
                root.errorMsg = parsed.message || "Authentication failed.";
                root.status = "error";
                dismissTimer.restart();
            } else {
                root.errorMsg = parsed.message || "Wrong password.";
                root.status = "error";
                root.password = "";
                shakeAnim.restart();
                errorResetTimer.restart();
            }
        }

        function authSuccess(data: string): void {
            let parsed = JSON.parse(data);
            if (parsed.cookie === root.cookie) {
                root.status = "success";
                dismissTimer.restart();
            }
        }
    }

    Timer {
        id: dismissTimer
        interval: 800
        onTriggered: root.dismiss()
    }

    Timer {
        id: errorResetTimer
        interval: 1500
        onTriggered: {
            if (root.status === "error") {
                root.status = "input";
            }
        }
    }

    LazyLoader {
        active: root.visible

        PanelWindow {
            id: window

            WlrLayershell.layer: WlrLayer.Overlay
            WlrLayershell.namespace: "quickshell-polkit"
            WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive

            anchors {
                top: true
                left: true
                right: true
                bottom: true
            }

            color: "transparent"

            // Backdrop
            Rectangle {
                id: backdrop
                anchors.fill: parent
                color: Qt.rgba(0, 0, 0, fadeIn.value * 0.4)

                NumberAnimation {
                    id: fadeIn
                    property: "value"
                    target: fadeIn
                    from: 0; to: 1
                    duration: Quill.Theme.animDuration
                    easing.type: Easing.OutCubic
                    running: true

                    property real value: 0
                }

                MouseArea {
                    anchors.fill: parent
                    onClicked: root.cancelAuth()
                }
            }

            // Auth card
            Rectangle {
                id: card
                anchors.centerIn: parent
                width: 400
                height: cardLayout.implicitHeight + 48
                radius: Quill.Theme.radiusLg
                color: Quill.Theme.surface0

                // Entrance animation
                scale: fadeIn.value * 0.05 + 0.95
                opacity: fadeIn.value

                // Shake animation
                transform: Translate { id: cardShake; x: 0 }
                SequentialAnimation {
                    id: shakeAnim
                    NumberAnimation { target: cardShake; property: "x"; to: 12; duration: 50 }
                    NumberAnimation { target: cardShake; property: "x"; to: -10; duration: 50 }
                    NumberAnimation { target: cardShake; property: "x"; to: 8; duration: 50 }
                    NumberAnimation { target: cardShake; property: "x"; to: -6; duration: 50 }
                    NumberAnimation { target: cardShake; property: "x"; to: 3; duration: 50 }
                    NumberAnimation { target: cardShake; property: "x"; to: 0; duration: 50 }
                }

                ColumnLayout {
                    id: cardLayout
                    anchors.fill: parent
                    anchors.margins: 24
                    spacing: 16

                    // Header
                    RowLayout {
                        Layout.alignment: Qt.AlignHCenter
                        spacing: 10

                        IconLock {
                            size: 22
                            color: root.status === "success" ? Quill.Theme.success
                                 : root.status === "error" ? Quill.Theme.error
                                 : Quill.Theme.primary
                            Behavior on color { ColorAnimation { duration: 200 } }
                        }

                        Quill.Label {
                            text: "Authentication Required"
                            variant: "heading"
                        }
                    }

                    // User
                    Quill.Label {
                        text: "Authenticating as " + root.userName
                        variant: "caption"
                        Layout.alignment: Qt.AlignHCenter
                        color: Quill.Theme.textSecondary
                    }

                    // Separator
                    Quill.Separator {}

                    // Message
                    Quill.Label {
                        text: root.message
                        variant: "body"
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                    }

                    // Password field
                    Quill.TextField {
                        id: passwordField
                        Layout.fillWidth: true
                        placeholder: "Password"
                        echoMode: TextInput.Password
                        enabled: root.status === "input" || root.status === "error"

                        Component.onCompleted: inputItem.forceActiveFocus()

                        onSubmitted: (text) => root.submitPassword()

                        Connections {
                            target: root
                            function onVisibleChanged() {
                                if (root.visible) passwordField.inputItem.forceActiveFocus();
                            }
                            function onStatusChanged() {
                                if (root.status === "input") {
                                    passwordField.text = "";
                                    passwordField.inputItem.forceActiveFocus();
                                }
                            }
                        }
                    }

                    // Bind password from TextField
                    Binding {
                        target: root
                        property: "password"
                        value: passwordField.text
                    }

                    // Error label
                    Quill.Label {
                        text: root.errorMsg
                        variant: "caption"
                        color: Quill.Theme.error
                        visible: root.errorMsg.length > 0
                        Layout.alignment: Qt.AlignHCenter
                    }

                    // Spinner while verifying
                    Quill.Spinner {
                        Layout.alignment: Qt.AlignHCenter
                        visible: root.status === "verifying"
                        size: "small"
                    }

                    // Buttons
                    RowLayout {
                        Layout.alignment: Qt.AlignRight
                        spacing: 8

                        Quill.Button {
                            text: "Cancel"
                            variant: "ghost"
                            onClicked: root.cancelAuth()
                        }

                        Quill.Button {
                            text: root.status === "success" ? "Authenticated" : "Authenticate"
                            variant: root.status === "success" ? "primary" : "secondary"
                            enabled: root.status === "input" || root.status === "error"
                            onClicked: root.submitPassword()
                        }
                    }
                }
            }

            // Keyboard handling
            Keys.onEscapePressed: root.cancelAuth()
        }
    }
}
