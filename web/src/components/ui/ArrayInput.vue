<script setup lang="ts">
import { computed, ref } from 'vue';

const props = withDefaults(
  defineProps<{
    modelValue?: string[];
    label?: string;
    placeholder?: string;
    hint?: string;
    suggestions?: string[];
    allowDuplicates?: boolean;
  }>(),
  {
    modelValue: () => [],
    placeholder: '输入内容后按回车或逗号添加，支持多行粘贴',
    suggestions: () => [],
    allowDuplicates: false
  }
);

const emit = defineEmits<{
  (e: 'update:modelValue', value: string[]): void;
}>();

const draft = ref('');
const items = computed(() => props.modelValue || []);

function addTokens(raw: string) {
  const parts = raw
    .split(/[\r\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0) return;

  const next = [...items.value];
  for (const p of parts) {
    if (props.allowDuplicates || !next.includes(p)) {
      next.push(p);
    }
  }
  emit('update:modelValue', next);
  draft.value = '';
}

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' || e.key === ',') {
    e.preventDefault();
    addTokens(draft.value);
  } else if (e.key === 'Backspace' && draft.value === '' && items.value.length > 0) {
    emit('update:modelValue', items.value.slice(0, -1));
  }
}

function handlePaste(e: ClipboardEvent) {
  const text = e.clipboardData?.getData('text') || '';
  if (text.includes('\n') || text.includes(',')) {
    e.preventDefault();
    addTokens(text);
  }
}

function removeAt(idx: number) {
  const next = items.value.filter((_, i) => i !== idx);
  emit('update:modelValue', next);
}

function addSuggestion(s: string) {
  addTokens(s);
}
</script>

<template>
  <div class="field">
    <div v-if="label" class="row-nowrap" style="justify-content: space-between">
      <label>{{ label }}</label>
      <button
        v-if="items.length > 0"
        type="button"
        class="chip-suggest-btn"
        style="border-style: solid"
        @click="emit('update:modelValue', [])"
      >
        清空 ({{ items.length }})
      </button>
    </div>

    <div class="chip-box">
      <span v-for="(item, idx) in items" :key="`${item}-${idx}`" class="chip">
        <span>{{ item }}</span>
        <button type="button" class="chip-remove" title="移除" @click="removeAt(idx)">×</button>
      </span>
      <input
        v-model="draft"
        type="text"
        class="chip-input"
        :placeholder="items.length === 0 ? placeholder : '继续输入回车添加...'"
        @keydown="handleKeydown"
        @paste="handlePaste"
        @blur="addTokens(draft)"
      />
    </div>

    <div v-if="suggestions.length > 0" class="chip-suggestions">
      <button
        v-for="s in suggestions"
        :key="s"
        type="button"
        class="chip-suggest-btn"
        @click="addSuggestion(s)"
      >
        + {{ s }}
      </button>
    </div>

    <span v-if="hint" class="field-hint">{{ hint }}</span>
  </div>
</template>
