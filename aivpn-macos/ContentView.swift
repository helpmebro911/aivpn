import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var loc: LocalizationManager
    
    @State private var connectionKey: String = ""
    @State private var keyName: String = ""
    @State private var showKeyInput: Bool = false
    @AppStorage("fullTunnel") private var fullTunnel: Bool = false
    @State private var editingKeyId: String?
    @State private var editingKeyName: String = ""
    @State private var showDeleteConfirm = false
    @State private var keyToDelete: ConnectionKey?

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 24, height: 24)
                Text("AIVPN")
                    .font(.headline)
                Spacer()
                // Language toggle
                Button(action: { loc.toggleLanguage() }) {
                    Text(loc.language == "en" ? "🇷🇺" : "🇬🇧")
                        .font(.title3)
                        .buttonStyle(.plain)
                }
                .buttonStyle(.plain)
                .help(loc.language == "en" ? "Русский" : "English")
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 8)

            Divider()

            // Helper status indicator
            HStack {
                Circle()
                    .fill(vpn.helperAvailable ? Color.green : Color.orange)
                    .frame(width: 8, height: 8)
                Text(vpn.helperAvailable
                     ? loc.t("helper_ready")
                     : loc.t("helper_missing"))
                    .font(.caption2)
                    .foregroundColor(vpn.helperAvailable ? .secondary : .orange)
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.top, 6)
            .padding(.bottom, 2)

            Divider()

            // Connection status
            VStack(spacing: 8) {
                HStack {
                    Circle()
                        .fill(vpn.isConnected ? Color.green : Color.gray)
                        .frame(width: 10, height: 10)
                    Text(vpn.isConnected ? loc.t("status_connected") :
                         vpn.isConnecting ? loc.t("connecting") :
                         loc.t("status_disconnected"))
                        .font(.subheadline)
                        .foregroundColor(vpn.isConnected ? .green : .secondary)
                    Spacer()
                }

                if vpn.isConnected {
                    HStack {
                        Text("↓ \(formatBytes(vpn.bytesReceived))")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Spacer()
                        Text("↑ \(formatBytes(vpn.bytesSent))")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                if let error = vpn.lastError {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                        .lineLimit(2)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            Divider()

            // Connection Keys List - ALWAYS VISIBLE
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(loc.t("connection_keys"))
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.secondary)
                    Spacer()
                    Button(action: {
                        withAnimation {
                            showKeyInput = true
                            keyName = ""
                            connectionKey = ""
                        }
                    }) {
                        Image(systemName: "plus.circle.fill")
                            .font(.caption)
                    }
                    .buttonStyle(.plain)
                    .help(loc.t("add_key"))
                }
                
                if vpn.keys.isEmpty {
                    // Empty state
                    VStack(spacing: 8) {
                        Image(systemName: "key")
                            .font(.system(size: 32))
                            .foregroundColor(.secondary)
                        Text(loc.t("no_keys_yet"))
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Button(loc.t("add_first_key")) {
                            withAnimation {
                                showKeyInput = true
                                keyName = ""
                                connectionKey = ""
                            }
                        }
                        .buttonStyle(.bordered)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 20)
                } else {
                    // Keys list
                    ScrollView {
                        LazyVStack(spacing: 6) {
                            ForEach(vpn.keys) { key in
                                KeyRowView(
                                    key: key,
                                    isSelected: vpn.selectedKeyId == key.id,
                                    isConnected: vpn.isConnected,
                                    onSelect: {
                                        vpn.selectKey(id: key.id)
                                    },
                                    onEdit: {
                                        editingKeyId = key.id
                                        editingKeyName = key.name
                                        keyName = key.name  // Заполнить поле имени текущим именем
                                        connectionKey = key.keyValue  // Показать текущий ключ
                                        withAnimation {
                                            showKeyInput = true
                                        }
                                    },
                                    onDelete: {
                                        keyToDelete = key
                                        showDeleteConfirm = true
                                    }
                                )
                                .contentShape(Rectangle()) // Make entire row clickable
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .frame(maxHeight: 180)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(Color(NSColor.controlBackgroundColor).opacity(0.3))
            .cornerRadius(8)

            Divider()

            // Add Key Form (shown when adding new key)
            if showKeyInput {
                VStack(spacing: 8) {
                    TextField(loc.t("key_name"), text: $keyName)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 11))
                    
                    SecureField(loc.t("enter_key"), text: $connectionKey)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 10))
                        .help("aivpn://...")

                    HStack {
                        Toggle(loc.t("full_tunnel"), isOn: $fullTunnel)
                            .toggleStyle(.checkbox)
                            .font(.caption)
                            .help(loc.t("full_tunnel_help"))
                        Spacer()
                    }
                    
                    HStack(spacing: 8) {
                        Button(loc.t("cancel")) {
                            withAnimation {
                                showKeyInput = false
                                keyName = ""
                                connectionKey = ""
                                editingKeyId = nil
                            }
                        }
                        .buttonStyle(.bordered)
                        
                        Button(loc.t("save_key")) {
                            let name = keyName.isEmpty ? "Key \(vpn.keys.count + 1)" : keyName
                            
                            if let editId = editingKeyId {
                                // Editing existing key - update both name and key value
                                if vpn.updateKey(id: editId, name: name, keyValue: connectionKey) {
                                    withAnimation {
                                        showKeyInput = false
                                        keyName = ""
                                        connectionKey = ""
                                        editingKeyId = nil
                                    }
                                } else {
                                    vpn.lastError = loc.t("duplicate_key")
                                }
                            } else {
                                // Adding new key
                                if vpn.addKey(name: name, keyValue: connectionKey) {
                                    withAnimation {
                                        showKeyInput = false
                                        keyName = ""
                                        connectionKey = ""
                                    }
                                } else {
                                    vpn.lastError = loc.t("duplicate_key")
                                }
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        
                        Spacer()
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }

            Divider()

            // Connect / Disconnect button
            Button(action: {
                if vpn.isConnected {
                    vpn.disconnect()
                } else {
                    guard let selectedKey = vpn.selectedKey ?? vpn.keys.first else {
                        vpn.lastError = loc.t("no_key_selected")
                        return
                    }
                    
                    if !vpn.helperAvailable {
                        vpn.checkHelperAvailable()
                    } else {
                        vpn.connect(key: selectedKey.keyValue, fullTunnel: fullTunnel)
                    }
                }
            }) {
                HStack {
                    Spacer()
                    if vpn.isConnecting {
                        ProgressView()
                            .scaleEffect(0.7)
                            .frame(width: 16, height: 16)
                        Text(loc.t("connecting"))
                    } else if vpn.isConnected {
                        Image(systemName: "stop.circle.fill")
                        Text(loc.t("disconnect"))
                    } else {
                        Image(systemName: "play.circle.fill")
                        Text(loc.t("connect"))
                    }
                    Spacer()
                }
                .padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)
            .tint(vpn.isConnected ? .red : .blue)
            .disabled(vpn.isConnecting || !vpn.helperAvailable || vpn.keys.isEmpty)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            Divider()

            // Footer
            HStack {
                Text("AIVPN v0.3.0")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                Spacer()
                Button(loc.t("quit")) {
                    vpn.disconnect()
                    NSApp.terminate(nil)
                }
                .font(.caption2)
                .buttonStyle(.plain)
                .foregroundColor(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
        .frame(width: 360, height: 420)
        .onReceive(vpn.$isConnected) { connected in
            if let appDelegate = NSApp.delegate as? AppDelegate {
                appDelegate.updateStatusIcon(connected: connected)
            }
        }
        .confirmationDialog(loc.t("delete_key_confirm"), isPresented: $showDeleteConfirm) {
            Button(loc.t("delete"), role: .destructive) {
                if let key = keyToDelete {
                    vpn.deleteKey(id: key.id)
                }
                keyToDelete = nil
            }
            Button(loc.t("cancel"), role: .cancel) {}
        } message: {
            Text(loc.t("delete_key_message"))
        }
    }

    private func formatBytes(_ bytes: Int64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 { return String(format: "%.1f KB", Double(bytes) / 1024.0) }
        if bytes < 1024 * 1024 * 1024 { return String(format: "%.1f MB", Double(bytes) / 1024.0 / 1024.0) }
        return String(format: "%.1f GB", Double(bytes) / 1024.0 / 1024.0 / 1024.0)
    }
}

// MARK: - Key Row View

struct KeyRowView: View {
    let key: ConnectionKey
    let isSelected: Bool
    let isConnected: Bool
    let onSelect: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void
    
    @State private var isHovering = false
    
    var body: some View {
        HStack(spacing: 10) {
            // Selection radio button - larger and more visible
            Circle()
                .fill(isSelected ? Color.green : Color.clear)
                .overlay(
                    Circle()
                        .stroke(isSelected ? Color.green : Color.gray, lineWidth: 2)
                )
                .frame(width: 16, height: 16)
            
            // Key info - full width clickable
            VStack(alignment: .leading, spacing: 3) {
                Text(key.name)
                    .font(.system(size: 12))
                    .fontWeight(isSelected ? .semibold : .regular)
                
                if let server = key.serverAddress {
                    HStack(spacing: 4) {
                        Image(systemName: "server.rack")
                            .font(.system(size: 9))
                        Text(server)
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                }
                if let vpnIP = key.vpnIP {
                    HStack(spacing: 4) {
                        Image(systemName: "network")
                            .font(.system(size: 9))
                        Text(vpnIP)
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // Connection status indicator
            if isSelected && isConnected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .font(.system(size: 16))
                    .padding(.trailing, 4)
            }
            
            // Actions menu - larger button
            Menu {
                Button(action: onEdit) {
                    Label("Edit", systemImage: "pencil")
                }
                Button(role: .destructive, action: onDelete) {
                    Label("Delete", systemImage: "trash")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .foregroundColor(.secondary)
                    .font(.system(size: 14))
                    .padding(4)
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(isSelected ? Color.green.opacity(0.1) : 
                      isHovering ? Color.gray.opacity(0.05) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isSelected ? Color.green.opacity(0.4) : Color.clear, lineWidth: 1.5)
        )
        .onHover { hovering in
            isHovering = hovering
        }
        .onTapGesture {
            onSelect()
        }
        // Make entire row clickable
        .contentShape(Rectangle())
    }
}
