import time

from flask import Flask, Response, request

from mesop.runtime import runtime
from mesop.server.server_utils import prefix_base_url


def configure_debug_routes(flask_app: Flask):
  @flask_app.route(prefix_base_url("/__hot-reload__"))
  def hot_reload() -> Response:
    counter = int(request.args["counter"])
    while True:
      if counter < runtime().hot_reload_counter:
        break
      # Sleep a short duration but not too short that we hog up excessive CPU.
      time.sleep(0.1)
    response = Response(str(runtime().hot_reload_counter), status=200)
    return response
