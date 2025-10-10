"""Add BGP Looking Glass devices table

Revision ID: 2025_10_09_bgp_looking_glass
Revises: 2025_10_09_saved_lists
Create Date: 2025-10-09 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2025_10_09_bgp_looking_glass'
down_revision = '2025_10_09_saved_lists'
branch_labels = None
depends_on = None


def upgrade():
    # Create bgp_looking_glass_devices table
    op.create_table('bgp_looking_glass_devices',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=True, default=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('bgp_looking_glass_devices')
