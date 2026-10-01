"""reports.metadatos: severidad, fuentes y trazabilidad del análisis de IA

Revision ID: b3f1c2d4e5a6
Revises: aa1144a4839f
Create Date: 2026-09-30 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3f1c2d4e5a6'
down_revision: Union[str, Sequence[str], None] = 'aa1144a4839f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Columna nullable: los informes existentes quedan intactos (metadatos = NULL)."""
    op.add_column('reports', sa.Column('metadatos', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('reports', 'metadatos')
