import re
import json
import torch
from datasets import Dataset
from trl import GRPOTrainer, GRPOConfig
from peft import LoraConfig
from sandbox import DockerCryptoSandbox

# Initialize Docker execution sandbox for reward evaluation
sandbox = DockerCryptoSandbox(image="crypto-sandbox:latest", timeout=15)

def docker_crypto_reward_func(prompts, completions, ground_truth_flag, **kwargs):
    """
    Evaluates each candidate solution produced by Llama-3 inside Docker.
    Returns +1.0 for capturing the exact ground-truth flag, +0.2 for valid compilation/execution, and 0.0 for errors.
    """
    rewards = []
    for completion, target in zip(completions, ground_truth_flag):
        code_match = re.search(r"```(?:python|sage)?\n(.*?)```", completion, re.DOTALL)
        if not code_match:
            rewards.append(0.0)
            continue

        code = code_match.group(1).strip()
        is_sage = "sage" in completion.lower() or "import sage" in code

        try:
            res = sandbox.execute(code=code, is_sage=is_sage, allow_network=False)
            stdout = res.get("stdout", "")

            # Check if ground truth flag is recovered
            if target in stdout:
                rewards.append(1.0)
            elif res["exit_code"] == 0 and len(stdout.strip()) > 0:
                rewards.append(0.2)  # Partial credit: valid code executed without crashing
            else:
                rewards.append(0.0)
        except Exception:
            rewards.append(0.0)

    return rewards

def prepare_llama3_dataset(jsonl_file: str) -> Dataset:
    """Formats synthetic challenges into Llama-3 instruction chat format."""
    with open(jsonl_file, "r", encoding="utf-8") as f:
        raw_data = [json.loads(line) for line in f]

    formatted_prompts = []
    target_flags = []

    for item in raw_data:
        prompt = (
            "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
            "You are an expert cryptographic exploit generator. Given a problem, output your mathematical "
            "reasoning inside <thought> tags, followed by executable Python or SageMath code enclosed in a markdown code block.\n"
            "<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
            f"{item['problem']}\n"
            "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
        )
        formatted_prompts.append(prompt)
        target_flags.append(item["ground_truth_flag"])

    return Dataset.from_dict({
        "prompt": formatted_prompts,
        "ground_truth_flag": target_flags
    })

def main():
    model_id = "meta-llama/Meta-Llama-3.1-8B-Instruct"

    # 1. Load generated dataset
    dataset = prepare_llama3_dataset("crypto_dataset.jsonl")

    # 2. Configure LoRA adapter for parameter-efficient training
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM"
    )

    # 3. Configure GRPO Hyperparameters
    training_args = GRPOConfig(
        output_dir="./llama3-crypto-grpo",
        learning_rate=5e-6,
        num_train_epochs=2,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        num_generations=4,             # Generates 4 candidate exploits per challenge for relative ranking
        max_prompt_length=512,
        max_completion_length=768,
        logging_steps=5,
        save_strategy="steps",
        save_steps=50,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
    )

    # 4. Instantiate GRPOTrainer
    trainer = GRPOTrainer(
        model=model_id,
        reward_funcs=[docker_crypto_reward_func],
        args=training_args,
        train_dataset=dataset,
        peft_config=lora_config,
    )

    print("Starting GRPO Reinforcement Learning for Llama-3...")
    trainer.train()
    trainer.save_model("./llama3-crypto-grpo-final")
    print("Training complete! Model saved to ./llama3-crypto-grpo-final")

if __name__ == "__main__":
    main()
