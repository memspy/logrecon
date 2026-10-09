"""
Streamlit dashboard for reviewing anomalous log entries and teaching
the model what counts as normal vs. a real threat. Reads alerts pushed
by ingest_service.py into the shared SQLite store.
"""

import json

import streamlit as st

from anomaly_detector import AnomalyDetector
from log_parser import LogParser
from personal_rules import PersonalRules, RuleRejected
from signature_rules import match as match_signature
from storage import AlertStore

RULES_PATH = 'personal_rules.json'
DB_PATH = 'alerts.db'

@st.cache_resource
def get_components():
    detector = AnomalyDetector()
    try:
        detector.load()
    except FileNotFoundError:
        pass
    return PersonalRules(rules_path=RULES_PATH), AlertStore(db_path=DB_PATH), LogParser(), detector

def render_manual_classification(rules, parser, detector, reviewer):
    with st.expander('📝 Ручная классификация'):
        raw_text = st.text_area('Строка лога', key='manual_log_input', height=80)

        if not raw_text.strip():
            return

        record = parser.parse_line(raw_text)
        vector = detector.vectorize([record])[0]

        signature = match_signature(record['raw'])
        if signature:
            category, description = signature
            st.warning(f'Совпадает с сигнатурой: {description} ({category})')

        status_line = f"service: {record.get('service')} | status: {record.get('status')} | format: {record.get('format')}"
        if detector.is_trained:
            score = float(detector.model.decision_function(vector)[0])
            verdict = 'аномалия' if detector.model.predict(vector)[0] == -1 else 'в пределах нормы'
            status_line += f" | Isolation Forest: {score:.3f} ({verdict})"
        st.caption(status_line)

        col1, col2 = st.columns(2)
        with col1:
            mark_normal = st.button('👍 Отметить как норму', key='manual_normal')
        with col2:
            mark_threat = st.button('⚠️ Отметить как угрозу', key='manual_threat')

        if mark_normal:
            try:
                rules.add_false_positive(vector, record['raw'], reviewer=reviewer)
                st.success('Добавлено в белый список')
            except RuleRejected as e:
                st.error(str(e))

        if mark_threat:
            try:
                rules.add_true_positive_threat(vector, record['raw'], reviewer=reviewer)
                st.success('Добавлено в чёрный список')
            except RuleRejected as e:
                st.error(str(e))

def render_signature_match(alert, store):
    with st.container(border=True):
        if alert.get('context_json'):
            category, description = json.loads(alert['context_json'])
        else:
            category, description = 'unknown', 'unknown'
        st.error(f'Известная сигнатура атаки: {description} ({category})')
        st.code(alert['raw'], language=None)
        st.caption(f"service: {alert.get('service')} | status: {alert.get('status')}")

        if st.button('✅ Принято в работу', key=f"sig_ack_{alert['id']}"):
            store.mark_reviewed(alert['id'])
            st.rerun()

def render_known_threat(alert, store):
    with st.container(border=True):
        st.error('Совпадение с подтверждённой угрозой')
        st.code(alert['raw'], language=None)
        st.caption(f"service: {alert.get('service')} | status: {alert.get('status')}")

        if st.button('✅ Принято в работу', key=f"ack_{alert['id']}"):
            store.mark_reviewed(alert['id'])
            st.rerun()

def render_sequence_incident(alert, store):
    with st.container(border=True):
        st.warning(f"Подозрительная последовательность событий (score {alert['anomaly_score']:.2f})")
        context = json.loads(alert['context_json']) if alert.get('context_json') else [alert['raw']]

        for line in context:
            prefix = '>>> ' if line == alert['raw'] else ''
            st.code(prefix + line, language=None)

        if st.button('✅ Принято в работу', key=f"seq_ack_{alert['id']}"):
            store.mark_reviewed(alert['id'])
            st.rerun()

def render_model_anomaly(alert, rules, store, reviewer):
    with st.container(border=True):
        col_info, col_actions = st.columns([4, 1])

        with col_info:
            st.code(alert['raw'], language=None)
            st.caption(
                f"service: {alert.get('service')} | "
                f"status: {alert.get('status')} | "
                f"score: {alert['anomaly_score']:.3f}"
            )

        with col_actions:
            vector = json.loads(alert['vector_json'])

            if st.button('👍 Это норма', key=f"ok_{alert['id']}"):
                try:
                    rules.add_false_positive(vector, alert['raw'], reviewer=reviewer)
                    store.mark_reviewed(alert['id'])
                    st.rerun()
                except RuleRejected as e:
                    st.error(str(e))

            if st.button('⚠️ Реальная угроза', key=f"threat_{alert['id']}"):
                try:
                    rules.add_true_positive_threat(vector, alert['raw'], reviewer=reviewer)
                    store.mark_reviewed(alert['id'])
                    st.rerun()
                except RuleRejected as e:
                    st.error(str(e))

def main():
    st.set_page_config(page_title='LogRecon', layout='wide')
    st.title('LogRecon')

    with st.sidebar:
        reviewer = st.text_input('Ваше имя (для аудита)', value=st.session_state.get('reviewer', ''))
        st.session_state['reviewer'] = reviewer
        if not reviewer:
            st.caption('Без имени решения будут записаны как "unknown"')

    rules, store, parser, detector = get_components()

    if st.button('🔄 Обновить'):
        st.rerun()

    render_manual_classification(rules, parser, detector, reviewer or 'unknown')

    alerts = store.get_pending()

    if not alerts:
        st.info('Нет подозрительных записей на проверке.')
        return

    signature_matches = [a for a in alerts if a['match_type'] == 'signature_match']
    known_threats = [a for a in alerts if a['match_type'] == 'known_threat']
    sequence_incidents = [a for a in alerts if a['match_type'] == 'sequence_anomaly']
    model_anomalies = [a for a in alerts if a['match_type'] == 'model_anomaly']

    if signature_matches:
        st.subheader(f'🚨 Известные сигнатуры атак ({len(signature_matches)})')
        for alert in signature_matches:
            render_signature_match(alert, store)

    if known_threats:
        st.subheader(f'Подтверждённые угрозы ({len(known_threats)})')
        for alert in known_threats:
            render_known_threat(alert, store)

    if sequence_incidents:
        st.subheader(f'Сложные инциденты — аномальные последовательности ({len(sequence_incidents)})')
        for alert in sequence_incidents:
            render_sequence_incident(alert, store)

    if model_anomalies:
        st.subheader(f'На классификацию ({len(model_anomalies)})')
        for alert in model_anomalies:
            render_model_anomaly(alert, rules, store, reviewer or 'unknown')

if __name__ == '__main__':
    main()
