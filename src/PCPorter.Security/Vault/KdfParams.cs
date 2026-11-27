namespace PCPorter.Security.Vault;

/// <summary>Argon2id cost. Defaults take roughly a second on a modern PC; the values are stored in the vault header.</summary>
public sealed record KdfParams(int MemoryKiB = 256 * 1024, int Iterations = 3, int Parallelism = 4);
