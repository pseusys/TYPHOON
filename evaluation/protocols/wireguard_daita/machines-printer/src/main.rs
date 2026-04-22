use maybenot_machines::{get_machine, StaticMachine};
use rand::rngs::SmallRng;
use rand::SeedableRng;

fn main() {
    let role = std::env::args().nth(1).expect("missing role argument");

    let static_machines: Vec<StaticMachine> = match role.as_str() {
        "server" => vec![
            StaticMachine::BreakPadServer,
            StaticMachine::ScramblerServer {
                interval: 0.1,
                min_count: 2.0,
                min_trail: 0.05,
                max_trail: 0.2,
            },
        ],
        "client" => vec![
            StaticMachine::BreakPadClient,
            StaticMachine::ScramblerClient,
        ],
        _ => panic!("invalid role: {}", role),
    };

    let mut rng = SmallRng::seed_from_u64(42);
    let machines = get_machine(&static_machines, &mut rng);
    for m in machines {
        println!("{}", m.serialize());
    }
}
