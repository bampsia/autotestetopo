import pandas as pd
import matplotlib.pyplot as plt

def load_data(filepath, scenario, size):
    with open(filepath, 'r') as file:
        lines = file.readlines()
    
    data = {"pktsent": [], "pktrecv": [], "pktlost": [], "bw": [], "jitter": []}
    
    for line in lines:
        for key in data.keys():
            if key in line:
                value = float(line.split(":")[1].strip())
                data[key].append(value)
    df = pd.DataFrame(data)
    df["scenario"] = scenario
    df["size"] = size
    return df

files = [

    ("semalt100", "Sem Alteração", 100),
    ("semalt200", "Sem Alteração", 200),
    ("semalt300", "Sem Alteração", 300),
    

    ("direta100", "Direta", 100),
    ("direta200", "Direta", 200),
    ("direta300", "Direta", 300),
    
 
    ("reversa100", "Reversa", 100),
    ("reversa200", "Reversa", 200),
    ("reversa300", "Reversa", 300),
]

all_data = pd.concat([load_data(f, s, sz) for f, s, sz in files], ignore_index=True)

grouped = all_data.groupby(["scenario", "size"])
averages = grouped.mean().reset_index()
errors = grouped.std().reset_index()

averages = averages.merge(errors, on=["scenario", "size"], suffixes=("", "_std"))

output_path = "test_results_scenarios.xlsx"
with pd.ExcelWriter(output_path) as writer:
    all_data.to_excel(writer, sheet_name="All Data", index=False)
    averages.to_excel(writer, sheet_name="Averages", index=False)

metrics = {
    "pktlost": "Pacotes Perdidos",
    "bw": "Largura de Banda",
    "jitter": "Jitter"
}

for metric, label in metrics.items():
    plt.figure(figsize=(10, 6))
    for scenario in averages["scenario"].unique():
        scenario_data = averages[averages["scenario"] == scenario]
        errors_data = averages[averages["scenario"] == scenario][f"{metric}_std"]
        plt.bar(
            scenario_data["size"] + {"Sem Alteração": -5, "Direta": 0, "Reversa": 5}[scenario],
            scenario_data[metric],
            yerr=errors_data,
            width=5,
            capsize=4,
            label=scenario
        )
    plt.title(f"Comparação de {label}")
    plt.xlabel("Taxa de bits na Reprodução")
    plt.ylabel(label)
    plt.xticks([100, 200, 300])
    plt.legend(title="Cenário")
    plt.grid(axis='y')
    plt.savefig(f"{metric}_bar_error.png")
    plt.close()

for metric in metrics.keys():
    nome_medida = metrics[metric]
    plt.figure(figsize=(10, 6))
    for scenario in averages["scenario"].unique():
        scenario_data = averages[averages["scenario"] == scenario]
        errors_data = averages[averages["scenario"] == scenario][f"{metric}_std"]
        plt.errorbar(
            scenario_data["size"], scenario_data[metric],
            yerr=errors_data,
            label=scenario,
            capsize=4, fmt='o-',
        )
    plt.title(f"Comparação de {nome_medida}")
    plt.xlabel("Taxa de bits na Reprodução")
    plt.ylabel(nome_medida)
    plt.xticks([100, 200, 300])
    plt.legend(title="Cenário")
    plt.grid()
    plt.savefig(f"{metric}_line_error.png")
    plt.close()
    
print("Dados e gráficos salvos.")
