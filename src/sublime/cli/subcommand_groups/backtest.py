"""CLI backtest subcommands."""

import os
import platform

import click

from sublime.__version__ import __version__
from sublime.cli.decorator import (
    echo_result,
    handle_exceptions,
    pass_api_client,
    MissingDetectionInput
)
from sublime.cli.helper import *


@click.group()
def backtest():
    """Backtest across historical messages in your Sublime environment."""
    pass

@backtest.command()
@click.option("-v", "--verbose", count=True, help="Verbose output")
@click.option("-k", "--api-key", help="Key to include in API requests")
@click.option(
    "-D", "--detections", "detections_path", 
    type=click.Path(exists=True), 
    help="Detections file or directory"
)
@click.option(
    "-d", "--detection", "detection_str", type=str,
    help=(
        "Raw detection. Instead of using a detections file, "
        "specify a single detection to be run directly surrounded "
        "by single quotes"
    )
)
@click.option(
    "-n", "--name", "detection_name", type=str,
    help=(
        "Detection name"
    )
)
@click.option("--after", "after", 
    type=click.DateTime(formats=get_datetime_formats()),
    help=(
        "Only analyze messages after this date. "
        "Default: 3 days ago. Format: ISO 8601"
    )
)
@click.option("--before", "before",
    type=click.DateTime(formats=get_datetime_formats()),
    help="Only analyze messages before this date. Format: ISO 8601"
)
@click.option(
    "-o", "--output", "output_file", type=click.File(mode="w"), 
    help="Output file"
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "txt"]),
    default="txt",
    help="Output format",
)
@pass_api_client
@click.pass_context
@echo_result
@handle_exceptions
def detections(
    context,
    api_client,
    api_key,
    detections_path,
    detection_str,
    detection_name,
    after,
    before,
    output_file,
    output_format,
    verbose,
):
    """Backtest a detection(s)."""

    if not detections_path and not detection_str:
        raise MissingDetectionInput

    if detections_path:
        if os.path.isfile(detections_path):
            with open(detections_path) as f:
                detections = load_detections(context, f)

        elif os.path.isdir(detections_path):
            detections = load_detections_path(context, detections_path)
    else:
        detections = [create_detection(detection_str)]

    results = api_client.backtest_detections(detections, after, before)

    return results