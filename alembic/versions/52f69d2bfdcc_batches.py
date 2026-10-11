"""batches y batch_items: lotes de indicadores definidos por el analista (Fase 7a)

Revision ID: 52f69d2bfdcc
Revises: b3f1c2d4e5a6
Create Date: 2026-10-10 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '52f69d2bfdcc'
down_revision: Union[str, Sequence[str], None] = 'b3f1c2d4e5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Solo agrega tablas: lo existente queda intacto."""
    op.create_table('batches',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=200), nullable=True),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('batch_items',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('batch_id', sa.Integer(), nullable=False),
    sa.Column('indicator_id', sa.Integer(), nullable=True),
    sa.Column('posicion', sa.Integer(), nullable=False),
    sa.Column('entrada', sa.String(length=2048), nullable=False),
    sa.Column('tipo', sa.String(length=16), nullable=True),
    sa.Column('ingesta', sa.String(), nullable=False),
    sa.Column('motivo', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['batch_id'], ['batches.id'], ),
    sa.ForeignKeyConstraint(['indicator_id'], ['indicators.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('batch_id', 'indicator_id', name='uq_batch_items_batch_indicator')
    )
    op.create_index(op.f('ix_batch_items_batch_id'), 'batch_items', ['batch_id'], unique=False)
    op.create_index(op.f('ix_batch_items_indicator_id'), 'batch_items', ['indicator_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_batch_items_indicator_id'), table_name='batch_items')
    op.drop_index(op.f('ix_batch_items_batch_id'), table_name='batch_items')
    op.drop_table('batch_items')
    op.drop_table('batches')
