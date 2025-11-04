package common

type Attack string

const (
	SignAttack         Attack = "sign"
	DarkAttack         Attack = "dark"
	EquivocationAttack Attack = "equivocation"
	CrashAttack        Attack = "crash"
	TimeAttack         Attack = "time"
)
