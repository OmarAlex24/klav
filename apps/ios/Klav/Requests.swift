import SwiftUI

/// The requests on top of the vault: agents asking to join, tasks to
/// decide, agents asking for something, then running tasks with «End
/// task» in view. Blue only here: it marks what agents do.
struct RequestsSection: View {
    @EnvironmentObject private var model: AppModel
    var highlighted: String?
    var review: (AgentItem) -> Void

    var body: some View {
        if !model.approvals.isEmpty || !model.registrations.isEmpty || !model.tasks.isEmpty {
            // The space above each card goes inside its ID, so scrolling to
            // the one a notification opened leaves its cross corners in view.
            VStack(alignment: .leading, spacing: 0) {
                ForEach(model.registrations, id: \.id) { agent in
                    RegistrationCard<AppModel>(agent: agent, highlighted: highlighted == agent.id) { review(agent) }
                        .padding(.top, 16)
                        .id(agent.id)
                }
                ForEach(model.tasks.filter { $0.status == "pending" }, id: \.decisionKey) { task in
                    PendingTaskCard<AppModel>(card: task, highlighted: highlighted == task.id)
                        .padding(.top, 16)
                        .id(task.id)
                }
                ForEach(model.approvals, id: \.decisionKey) { approval in
                    ApprovalCard<AppModel>(approval: approval, highlighted: highlighted == approval.id)
                        .padding(.top, 16)
                        .id(approval.id)
                }
                ForEach(model.tasks.filter { $0.status == "approved" }, id: \.id) { task in
                    LiveTaskCard<AppModel>(card: task, highlighted: highlighted == task.id)
                        .padding(.top, 16)
                        .id(task.id)
                }
            }
            .padding(.top, 2)
        }
    }
}

extension AppModel: RequestsModel {
    var waitingForPresence: String { String(localized: "Waiting for Face ID…") }

    func agentProjects() async throws -> [ProjectInfo] {
        guard let service else { throw KlavError.Locked }
        return try await service.run { core, _ in try core.projects(vaultId: nil) }
    }
}

extension AppModel: FixOffering {
    func offerFix(_ input: OfferInput, agent: String, offered: @escaping @MainActor (TaskItem) -> Void) async throws {
        let task: TaskItem = try await offerFix(input, agent: agent)
        offered(task)
    }
}
