package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"
)

// PeakUsage holds the schema definition for peak resource usage tracking.
//
// 删除策略：硬删除
// PeakUsage 使用硬删除，因为删除通过 JOIN 查询处理，无需软删除。
type PeakUsage struct {
	ent.Schema
}

func (PeakUsage) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "peak_usages"},
	}
}

func (PeakUsage) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (PeakUsage) Fields() []ent.Field {
	return []ent.Field{
		field.String("entity_type").
			MaxLen(20).
			NotEmpty().
			Comment("account or user"),
		field.Int64("entity_id").
			Positive(),
		field.Int("peak_concurrency").
			Default(0).
			Min(0),
		field.Int("peak_sessions").
			Default(0).
			Min(0),
		field.Int("peak_rpm").
			Default(0).
			Min(0),
		field.Time("reset_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{
				dialect.Postgres: "timestamptz",
			}),
	}
}

func (PeakUsage) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("entity_type", "entity_id").Unique(),
	}
}
