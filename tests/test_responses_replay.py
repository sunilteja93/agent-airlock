from dataclasses import dataclass

from airlock.responses_replay import output_items, user_message


@dataclass
class FakeItem:
    payload: dict

    def model_dump(self, mode="json", exclude_none=True):
        assert mode == "json"
        return dict(self.payload)


@dataclass
class FakeResponse:
    output: list


def test_user_message_uses_typed_responses_input():
    message = user_message("hello")
    assert message == {
        "role": "user",
        "content": [{"type": "input_text", "text": "hello"}],
    }


def test_replay_preserves_function_call_fields():
    response = FakeResponse(
        output=[
            FakeItem(
                {
                    "id": "fc_1",
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "repo_read",
                    "arguments": '{"path":"app.py"}',
                    "status": "completed",
                }
            )
        ]
    )
    items = output_items(response)
    assert items[0]["call_id"] == "call_1"
    assert items[0]["name"] == "repo_read"


def test_replay_preserves_encrypted_reasoning_and_summary():
    response = FakeResponse(
        output=[
            FakeItem(
                {
                    "id": "rs_1",
                    "type": "reasoning",
                    "encrypted_content": "opaque",
                    "summary": [],
                    "status": "completed",
                }
            )
        ]
    )
    items = output_items(response)
    assert items[0]["encrypted_content"] == "opaque"
    assert items[0]["summary"] == []


def test_replay_adds_empty_reasoning_summary_when_missing():
    response = FakeResponse(
        output=[
            FakeItem(
                {
                    "id": "rs_2",
                    "type": "reasoning",
                    "encrypted_content": "opaque",
                }
            )
        ]
    )
    items = output_items(response)
    assert items[0]["summary"] == []
