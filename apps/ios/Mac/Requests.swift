import SwiftUI

/// What the agents ask for, in the order the iPhone shows it: agents asking
/// to join, tasks to decide, single requests, then running tasks with «End
/// task». The cards are the iPhone's (Shared/App/RequestCards.swift).
struct RequestsPane: View {
    @EnvironmentObject private var model: MacModel
    @State private var reviewing: AgentItem?

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Requests",
                       detail: model.pendingCount == 0 ? nil : String(localized: "\(Int64(model.pendingCount)) waiting for you"))
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if model.registrations.isEmpty && model.tasks.isEmpty && model.approvals.isEmpty {
                        empty
                    }
                    ForEach(model.registrations) { agent in
                        RegistrationCard<MacModel>(agent: agent, warning: model.sameName(as: agent)) { reviewing = agent }
                    }
                    ForEach(model.tasks.filter { $0.status == "pending" }, id: \.decisionKey) { task in
                        PendingTaskCard<MacModel>(card: task)
                    }
                    ForEach(model.approvals, id: \.decisionKey) { approval in
                        ApprovalCard<MacModel>(approval: approval)
                    }
                    ForEach(model.tasks.filter { $0.status == "approved" }) { task in
                        LiveTaskCard<MacModel>(card: task)
                    }
                }
                .frame(maxWidth: 620, alignment: .leading)
                .padding(.horizontal, 28)
                .padding(.vertical, 24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .sheet(item: $reviewing) { agent in
            AgentReviewView<MacModel>(agent: agent, warning: model.sameName(as: agent),
                                      matched: model.launchedMatch(agent))
                .environmentObject(model)
                .frame(width: 480, height: 640)
        }
        .onAppear { model.loadRequests() }
    }

    private var empty: some View {
        HStack(alignment: .top, spacing: 18) {
            DitherView(kind: .band, palette: .blue, pixel: 3)
                .frame(width: 40, height: 88)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text("Nothing is waiting")
                    .font(.ui(16, .medium)).foregroundStyle(Palette.tinta)
                Text("When an agent asks for something its policy says to confirm, it shows up here and in a notification. Approving here works for the CLI and the extension too.")
                    .font(.ui(13)).foregroundStyle(Palette.gris)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.top, 8)
    }
}

/// The top of a pane: its name and a short line about it, at the height of
/// the vault's search bar.
struct PaneHeader: View {
    let title: LocalizedStringKey
    var detail: String?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(title).font(.ui(15, .semibold)).foregroundStyle(Palette.tinta)
            if let detail {
                Text(verbatim: detail).font(.ui(13)).foregroundStyle(Palette.gris)
            }
            Spacer()
        }
        .padding(.horizontal, 28)
        .frame(height: 52)
        .overlay(alignment: .bottom) { Rule() }
    }
}
