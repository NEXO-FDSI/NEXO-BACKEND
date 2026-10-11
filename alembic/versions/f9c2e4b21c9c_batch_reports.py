"""batch_reports y batch_validation: informe conjunto del lote y su validación (Fase 7c)

Revision ID: f9c2e4b21c9c
Revises: 52f69d2bfdcc
Create Date: 2026-10-10 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f9c2e4b21c9c'
down_revision: Union[str, Sequence[str], None] = '52f69d2bfdcc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Solo agrega tablas: lo existente queda intacto."""
    op.create_table('batch_reports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('batch_id', sa.Integer(), nullable=False),
    sa.Column('contenido', sa.Text(), nullable=False),
    sa.Column('conclusion', sa.String(), nullable=False),
    sa.Column('metadatos', sa.Text(), nullable=True),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['batch_id'], ['batches.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_batch_reports_batch_id'), 'batch_reports', ['batch_id'], unique=False)
    op.create_table('batch_validation',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('batch_report_id', sa.Integer(), nullable=False),
    sa.Column('decision', sa.String(), nullable=False),
    sa.Column('analista', sa.String(), nullable=True),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['batch_report_id'], ['batch_reports.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_batch_validation_batch_report_id'), 'batch_validation', ['batch_report_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_batch_validation_batch_report_id'), table_name='batch_validation')
    op.drop_table('batch_validation')
    op.drop_index(op.f('ix_batch_reports_batch_id'), table_name='batch_reports')
    op.drop_table('batch_reports')
